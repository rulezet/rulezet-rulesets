rule TTP_XOR_WriteProcessMemory_4df7 {
  strings:
    $key_4df7 = { 1a 85 [2] 28 a7 [2] 2e 92 [2] 00 92 [2] 3f 8e }

  condition:
    any of them
}