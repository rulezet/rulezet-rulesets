rule TTP_XOR_WriteProcessMemory_1a02 {
  strings:
    $key_1a02 = { 4d 70 [2] 7f 52 [2] 79 67 [2] 57 67 [2] 68 7b }

  condition:
    any of them
}