rule TTP_XOR_WriteProcessMemory_b887 {
  strings:
    $key_b887 = { ef f5 [2] dd d7 [2] db e2 [2] f5 e2 [2] ca fe }

  condition:
    any of them
}