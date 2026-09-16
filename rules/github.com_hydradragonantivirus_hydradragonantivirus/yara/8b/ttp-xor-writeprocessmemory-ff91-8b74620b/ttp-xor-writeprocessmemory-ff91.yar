rule TTP_XOR_WriteProcessMemory_ff91 {
  strings:
    $key_ff91 = { a8 e3 [2] 9a c1 [2] 9c f4 [2] b2 f4 [2] 8d e8 }

  condition:
    any of them
}