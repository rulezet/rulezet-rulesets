rule TTP_XOR_WriteProcessMemory_ba80 {
  strings:
    $key_ba80 = { ed f2 [2] df d0 [2] d9 e5 [2] f7 e5 [2] c8 f9 }

  condition:
    any of them
}