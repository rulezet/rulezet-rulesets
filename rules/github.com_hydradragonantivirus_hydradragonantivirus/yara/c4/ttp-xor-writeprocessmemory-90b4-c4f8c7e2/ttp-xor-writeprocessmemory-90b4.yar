rule TTP_XOR_WriteProcessMemory_90b4 {
  strings:
    $key_90b4 = { c7 c6 [2] f5 e4 [2] f3 d1 [2] dd d1 [2] e2 cd }

  condition:
    any of them
}