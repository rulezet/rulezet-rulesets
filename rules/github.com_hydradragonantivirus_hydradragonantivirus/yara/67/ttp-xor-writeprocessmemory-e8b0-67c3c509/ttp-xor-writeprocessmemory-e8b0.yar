rule TTP_XOR_WriteProcessMemory_e8b0 {
  strings:
    $key_e8b0 = { bf c2 [2] 8d e0 [2] 8b d5 [2] a5 d5 [2] 9a c9 }

  condition:
    any of them
}