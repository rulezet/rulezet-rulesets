rule TTP_XOR_WriteProcessMemory_96d5 {
  strings:
    $key_96d5 = { c1 a7 [2] f3 85 [2] f5 b0 [2] db b0 [2] e4 ac }

  condition:
    any of them
}