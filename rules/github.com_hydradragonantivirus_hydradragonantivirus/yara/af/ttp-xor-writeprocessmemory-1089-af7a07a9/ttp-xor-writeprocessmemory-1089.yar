rule TTP_XOR_WriteProcessMemory_1089 {
  strings:
    $key_1089 = { 47 fb [2] 75 d9 [2] 73 ec [2] 5d ec [2] 62 f0 }

  condition:
    any of them
}