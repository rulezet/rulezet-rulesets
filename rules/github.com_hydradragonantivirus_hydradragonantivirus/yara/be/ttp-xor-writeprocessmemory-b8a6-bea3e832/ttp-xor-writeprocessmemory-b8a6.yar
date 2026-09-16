rule TTP_XOR_WriteProcessMemory_b8a6 {
  strings:
    $key_b8a6 = { ef d4 [2] dd f6 [2] db c3 [2] f5 c3 [2] ca df }

  condition:
    any of them
}