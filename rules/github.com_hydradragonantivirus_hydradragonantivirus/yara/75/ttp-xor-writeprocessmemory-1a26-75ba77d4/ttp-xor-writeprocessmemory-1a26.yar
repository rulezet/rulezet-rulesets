rule TTP_XOR_WriteProcessMemory_1a26 {
  strings:
    $key_1a26 = { 4d 54 [2] 7f 76 [2] 79 43 [2] 57 43 [2] 68 5f }

  condition:
    any of them
}