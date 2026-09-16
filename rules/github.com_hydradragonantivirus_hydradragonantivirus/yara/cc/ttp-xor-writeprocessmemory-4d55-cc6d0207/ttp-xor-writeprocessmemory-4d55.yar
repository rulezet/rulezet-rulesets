rule TTP_XOR_WriteProcessMemory_4d55 {
  strings:
    $key_4d55 = { 1a 27 [2] 28 05 [2] 2e 30 [2] 00 30 [2] 3f 2c }

  condition:
    any of them
}