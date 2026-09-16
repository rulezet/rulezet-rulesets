rule TTP_XOR_WriteProcessMemory_1a73 {
  strings:
    $key_1a73 = { 4d 01 [2] 7f 23 [2] 79 16 [2] 57 16 [2] 68 0a }

  condition:
    any of them
}