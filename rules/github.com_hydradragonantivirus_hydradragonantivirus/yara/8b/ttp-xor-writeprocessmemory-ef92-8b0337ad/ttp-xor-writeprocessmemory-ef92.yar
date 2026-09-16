rule TTP_XOR_WriteProcessMemory_ef92 {
  strings:
    $key_ef92 = { b8 e0 [2] 8a c2 [2] 8c f7 [2] a2 f7 [2] 9d eb }

  condition:
    any of them
}