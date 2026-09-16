rule TTP_XOR_WriteProcessMemory_5e89 {
  strings:
    $key_5e89 = { 09 fb [2] 3b d9 [2] 3d ec [2] 13 ec [2] 2c f0 }

  condition:
    any of them
}