rule TTP_XOR_WriteProcessMemory_da89 {
  strings:
    $key_da89 = { 8d fb [2] bf d9 [2] b9 ec [2] 97 ec [2] a8 f0 }

  condition:
    any of them
}