rule TTP_XOR_WriteProcessMemory_e8b4 {
  strings:
    $key_e8b4 = { bf c6 [2] 8d e4 [2] 8b d1 [2] a5 d1 [2] 9a cd }

  condition:
    any of them
}