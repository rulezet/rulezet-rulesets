rule TTP_XOR_WriteProcessMemory_ba81 {
  strings:
    $key_ba81 = { ed f3 [2] df d1 [2] d9 e4 [2] f7 e4 [2] c8 f8 }

  condition:
    any of them
}