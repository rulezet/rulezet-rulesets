rule TTP_XOR_WriteProcessMemory_e1d4 {
  strings:
    $key_e1d4 = { b6 a6 [2] 84 84 [2] 82 b1 [2] ac b1 [2] 93 ad }

  condition:
    any of them
}