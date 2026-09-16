rule TTP_XOR_WriteProcessMemory_1a63 {
  strings:
    $key_1a63 = { 4d 11 [2] 7f 33 [2] 79 06 [2] 57 06 [2] 68 1a }

  condition:
    any of them
}