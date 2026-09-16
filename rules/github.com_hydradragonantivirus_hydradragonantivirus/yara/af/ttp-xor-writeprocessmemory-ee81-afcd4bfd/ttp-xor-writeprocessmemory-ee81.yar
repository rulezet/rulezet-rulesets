rule TTP_XOR_WriteProcessMemory_ee81 {
  strings:
    $key_ee81 = { b9 f3 [2] 8b d1 [2] 8d e4 [2] a3 e4 [2] 9c f8 }

  condition:
    any of them
}