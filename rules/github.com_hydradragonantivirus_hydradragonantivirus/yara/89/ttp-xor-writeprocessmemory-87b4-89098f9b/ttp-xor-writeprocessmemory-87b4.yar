rule TTP_XOR_WriteProcessMemory_87b4 {
  strings:
    $key_87b4 = { d0 c6 [2] e2 e4 [2] e4 d1 [2] ca d1 [2] f5 cd }

  condition:
    any of them
}