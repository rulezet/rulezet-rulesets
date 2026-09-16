rule TTP_XOR_WriteProcessMemory_3ed5 {
  strings:
    $key_3ed5 = { 69 a7 [2] 5b 85 [2] 5d b0 [2] 73 b0 [2] 4c ac }

  condition:
    any of them
}