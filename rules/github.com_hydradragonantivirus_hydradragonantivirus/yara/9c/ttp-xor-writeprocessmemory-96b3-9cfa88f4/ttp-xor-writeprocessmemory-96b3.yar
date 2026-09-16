rule TTP_XOR_WriteProcessMemory_96b3 {
  strings:
    $key_96b3 = { c1 c1 [2] f3 e3 [2] f5 d6 [2] db d6 [2] e4 ca }

  condition:
    any of them
}