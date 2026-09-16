rule TTP_XOR_WriteProcessMemory_4b82 {
  strings:
    $key_4b82 = { 1c f0 [2] 2e d2 [2] 28 e7 [2] 06 e7 [2] 39 fb }

  condition:
    any of them
}