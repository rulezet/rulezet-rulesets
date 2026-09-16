rule TTP_XOR_WriteProcessMemory_1af2 {
  strings:
    $key_1af2 = { 4d 80 [2] 7f a2 [2] 79 97 [2] 57 97 [2] 68 8b }

  condition:
    any of them
}