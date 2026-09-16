rule TTP_XOR_WriteProcessMemory_c589 {
  strings:
    $key_c589 = { 92 fb [2] a0 d9 [2] a6 ec [2] 88 ec [2] b7 f0 }

  condition:
    any of them
}