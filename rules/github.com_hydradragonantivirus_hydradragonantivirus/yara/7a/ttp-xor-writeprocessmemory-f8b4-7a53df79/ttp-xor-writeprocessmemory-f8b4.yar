rule TTP_XOR_WriteProcessMemory_f8b4 {
  strings:
    $key_f8b4 = { af c6 [2] 9d e4 [2] 9b d1 [2] b5 d1 [2] 8a cd }

  condition:
    any of them
}