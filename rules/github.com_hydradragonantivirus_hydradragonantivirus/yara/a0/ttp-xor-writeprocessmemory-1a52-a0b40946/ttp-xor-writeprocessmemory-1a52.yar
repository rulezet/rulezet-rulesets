rule TTP_XOR_WriteProcessMemory_1a52 {
  strings:
    $key_1a52 = { 4d 20 [2] 7f 02 [2] 79 37 [2] 57 37 [2] 68 2b }

  condition:
    any of them
}