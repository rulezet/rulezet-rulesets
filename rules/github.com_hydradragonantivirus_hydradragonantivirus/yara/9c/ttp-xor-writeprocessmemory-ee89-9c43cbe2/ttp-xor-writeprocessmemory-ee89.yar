rule TTP_XOR_WriteProcessMemory_ee89 {
  strings:
    $key_ee89 = { b9 fb [2] 8b d9 [2] 8d ec [2] a3 ec [2] 9c f0 }

  condition:
    any of them
}