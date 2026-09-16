rule TTP_XOR_WriteProcessMemory_6f96 {
  strings:
    $key_6f96 = { 38 e4 [2] 0a c6 [2] 0c f3 [2] 22 f3 [2] 1d ef }

  condition:
    any of them
}