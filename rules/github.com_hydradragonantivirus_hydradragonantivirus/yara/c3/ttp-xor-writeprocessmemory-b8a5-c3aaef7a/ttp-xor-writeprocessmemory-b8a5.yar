rule TTP_XOR_WriteProcessMemory_b8a5 {
  strings:
    $key_b8a5 = { ef d7 [2] dd f5 [2] db c0 [2] f5 c0 [2] ca dc }

  condition:
    any of them
}