rule TTP_XOR_WriteProcessMemory_7db5 {
  strings:
    $key_7db5 = { 2a c7 [2] 18 e5 [2] 1e d0 [2] 30 d0 [2] 0f cc }

  condition:
    any of them
}