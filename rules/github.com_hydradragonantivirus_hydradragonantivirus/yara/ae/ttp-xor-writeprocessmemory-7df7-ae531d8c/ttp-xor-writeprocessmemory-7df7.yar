rule TTP_XOR_WriteProcessMemory_7df7 {
  strings:
    $key_7df7 = { 2a 85 [2] 18 a7 [2] 1e 92 [2] 30 92 [2] 0f 8e }

  condition:
    any of them
}