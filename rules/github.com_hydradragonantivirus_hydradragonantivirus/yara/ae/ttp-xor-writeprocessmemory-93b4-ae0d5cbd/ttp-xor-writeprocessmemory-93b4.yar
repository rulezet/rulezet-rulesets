rule TTP_XOR_WriteProcessMemory_93b4 {
  strings:
    $key_93b4 = { c4 c6 [2] f6 e4 [2] f0 d1 [2] de d1 [2] e1 cd }

  condition:
    any of them
}