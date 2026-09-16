rule TTP_XOR_WriteProcessMemory_e1d0 {
  strings:
    $key_e1d0 = { b6 a2 [2] 84 80 [2] 82 b5 [2] ac b5 [2] 93 a9 }

  condition:
    any of them
}