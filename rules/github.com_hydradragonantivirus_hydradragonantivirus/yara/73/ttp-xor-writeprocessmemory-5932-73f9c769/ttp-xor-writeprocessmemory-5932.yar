rule TTP_XOR_WriteProcessMemory_5932 {
  strings:
    $key_5932 = { 0e 40 [2] 3c 62 [2] 3a 57 [2] 14 57 [2] 2b 4b }

  condition:
    any of them
}