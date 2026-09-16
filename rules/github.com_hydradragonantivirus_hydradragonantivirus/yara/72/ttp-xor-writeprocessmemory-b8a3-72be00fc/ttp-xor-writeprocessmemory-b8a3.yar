rule TTP_XOR_WriteProcessMemory_b8a3 {
  strings:
    $key_b8a3 = { ef d1 [2] dd f3 [2] db c6 [2] f5 c6 [2] ca da }

  condition:
    any of them
}