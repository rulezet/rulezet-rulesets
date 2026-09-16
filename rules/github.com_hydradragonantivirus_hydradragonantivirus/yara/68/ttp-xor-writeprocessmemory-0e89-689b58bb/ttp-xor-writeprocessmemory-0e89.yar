rule TTP_XOR_WriteProcessMemory_0e89 {
  strings:
    $key_0e89 = { 59 fb [2] 6b d9 [2] 6d ec [2] 43 ec [2] 7c f0 }

  condition:
    any of them
}