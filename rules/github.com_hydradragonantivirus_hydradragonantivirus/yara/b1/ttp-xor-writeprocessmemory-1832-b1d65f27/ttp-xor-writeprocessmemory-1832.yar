rule TTP_XOR_WriteProcessMemory_1832 {
  strings:
    $key_1832 = { 4f 40 [2] 7d 62 [2] 7b 57 [2] 55 57 [2] 6a 4b }

  condition:
    any of them
}