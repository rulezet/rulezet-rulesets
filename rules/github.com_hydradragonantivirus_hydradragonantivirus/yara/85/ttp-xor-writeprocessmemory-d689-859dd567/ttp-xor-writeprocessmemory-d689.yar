rule TTP_XOR_WriteProcessMemory_d689 {
  strings:
    $key_d689 = { 81 fb [2] b3 d9 [2] b5 ec [2] 9b ec [2] a4 f0 }

  condition:
    any of them
}