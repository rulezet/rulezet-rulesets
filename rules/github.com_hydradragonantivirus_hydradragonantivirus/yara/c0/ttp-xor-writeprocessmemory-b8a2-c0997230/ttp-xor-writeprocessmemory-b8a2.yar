rule TTP_XOR_WriteProcessMemory_b8a2 {
  strings:
    $key_b8a2 = { ef d0 [2] dd f2 [2] db c7 [2] f5 c7 [2] ca db }

  condition:
    any of them
}