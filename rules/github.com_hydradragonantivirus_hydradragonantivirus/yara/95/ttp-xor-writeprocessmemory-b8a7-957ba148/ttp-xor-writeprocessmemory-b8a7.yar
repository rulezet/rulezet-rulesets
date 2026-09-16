rule TTP_XOR_WriteProcessMemory_b8a7 {
  strings:
    $key_b8a7 = { ef d5 [2] dd f7 [2] db c2 [2] f5 c2 [2] ca de }

  condition:
    any of them
}