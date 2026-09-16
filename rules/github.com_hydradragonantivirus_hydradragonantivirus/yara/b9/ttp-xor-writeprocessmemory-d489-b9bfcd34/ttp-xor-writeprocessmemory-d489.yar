rule TTP_XOR_WriteProcessMemory_d489 {
  strings:
    $key_d489 = { 83 fb [2] b1 d9 [2] b7 ec [2] 99 ec [2] a6 f0 }

  condition:
    any of them
}