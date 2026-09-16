rule TTP_XOR_WriteProcessMemory_7089 {
  strings:
    $key_7089 = { 27 fb [2] 15 d9 [2] 13 ec [2] 3d ec [2] 02 f0 }

  condition:
    any of them
}