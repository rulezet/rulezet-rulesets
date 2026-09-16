rule TTP_XOR_WriteProcessMemory_b882 {
  strings:
    $key_b882 = { ef f0 [2] dd d2 [2] db e7 [2] f5 e7 [2] ca fb }

  condition:
    any of them
}