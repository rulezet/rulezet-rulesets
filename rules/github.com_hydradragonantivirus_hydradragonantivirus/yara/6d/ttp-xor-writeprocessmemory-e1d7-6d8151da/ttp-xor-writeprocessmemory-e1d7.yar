rule TTP_XOR_WriteProcessMemory_e1d7 {
  strings:
    $key_e1d7 = { b6 a5 [2] 84 87 [2] 82 b2 [2] ac b2 [2] 93 ae }

  condition:
    any of them
}