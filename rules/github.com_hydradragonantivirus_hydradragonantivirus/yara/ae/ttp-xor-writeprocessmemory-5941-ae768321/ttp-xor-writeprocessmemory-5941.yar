rule TTP_XOR_WriteProcessMemory_5941 {
  strings:
    $key_5941 = { 0e 33 [2] 3c 11 [2] 3a 24 [2] 14 24 [2] 2b 38 }

  condition:
    any of them
}