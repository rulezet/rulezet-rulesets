rule TTP_XOR_WriteProcessMemory_0ed5 {
  strings:
    $key_0ed5 = { 59 a7 [2] 6b 85 [2] 6d b0 [2] 43 b0 [2] 7c ac }

  condition:
    any of them
}