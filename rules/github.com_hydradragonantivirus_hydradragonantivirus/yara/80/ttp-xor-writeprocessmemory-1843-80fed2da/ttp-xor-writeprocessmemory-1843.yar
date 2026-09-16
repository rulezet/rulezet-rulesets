rule TTP_XOR_WriteProcessMemory_1843 {
  strings:
    $key_1843 = { 4f 31 [2] 7d 13 [2] 7b 26 [2] 55 26 [2] 6a 3a }

  condition:
    any of them
}