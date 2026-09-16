rule TTP_XOR_WriteProcessMemory_7d85 {
  strings:
    $key_7d85 = { 2a f7 [2] 18 d5 [2] 1e e0 [2] 30 e0 [2] 0f fc }

  condition:
    any of them
}