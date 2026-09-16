rule TTP_XOR_WriteProcessMemory_ba86 {
  strings:
    $key_ba86 = { ed f4 [2] df d6 [2] d9 e3 [2] f7 e3 [2] c8 ff }

  condition:
    any of them
}