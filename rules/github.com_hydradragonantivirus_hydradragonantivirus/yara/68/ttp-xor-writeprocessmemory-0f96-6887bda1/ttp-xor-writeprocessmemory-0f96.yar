rule TTP_XOR_WriteProcessMemory_0f96 {
  strings:
    $key_0f96 = { 58 e4 [2] 6a c6 [2] 6c f3 [2] 42 f3 [2] 7d ef }

  condition:
    any of them
}