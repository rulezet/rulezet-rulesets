rule TTP_XOR_WriteProcessMemory_c289 {
  strings:
    $key_c289 = { 95 fb [2] a7 d9 [2] a1 ec [2] 8f ec [2] b0 f0 }

  condition:
    any of them
}