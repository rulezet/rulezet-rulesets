rule TTP_XOR_WriteProcessMemory_ca89 {
  strings:
    $key_ca89 = { 9d fb [2] af d9 [2] a9 ec [2] 87 ec [2] b8 f0 }

  condition:
    any of them
}