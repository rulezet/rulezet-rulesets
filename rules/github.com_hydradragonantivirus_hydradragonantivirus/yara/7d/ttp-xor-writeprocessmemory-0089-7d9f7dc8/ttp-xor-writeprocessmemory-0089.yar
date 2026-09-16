rule TTP_XOR_WriteProcessMemory_0089 {
  strings:
    $key_0089 = { 57 fb [2] 65 d9 [2] 63 ec [2] 4d ec [2] 72 f0 }

  condition:
    any of them
}