rule TTP_XOR_WriteProcessMemory_ef96 {
  strings:
    $key_ef96 = { b8 e4 [2] 8a c6 [2] 8c f3 [2] a2 f3 [2] 9d ef }

  condition:
    any of them
}