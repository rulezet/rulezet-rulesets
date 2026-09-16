rule TTP_XOR_WriteProcessMemory_7dd5 {
  strings:
    $key_7dd5 = { 2a a7 [2] 18 85 [2] 1e b0 [2] 30 b0 [2] 0f ac }

  condition:
    any of them
}