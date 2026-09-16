rule TTP_XOR_WriteProcessMemory_5f96 {
  strings:
    $key_5f96 = { 08 e4 [2] 3a c6 [2] 3c f3 [2] 12 f3 [2] 2d ef }

  condition:
    any of them
}