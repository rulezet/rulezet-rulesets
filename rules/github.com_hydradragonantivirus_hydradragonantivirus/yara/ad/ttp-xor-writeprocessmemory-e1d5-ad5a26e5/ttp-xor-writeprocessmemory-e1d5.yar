rule TTP_XOR_WriteProcessMemory_e1d5 {
  strings:
    $key_e1d5 = { b6 a7 [2] 84 85 [2] 82 b0 [2] ac b0 [2] 93 ac }

  condition:
    any of them
}