rule TTP_XOR_WriteProcessMemory_96c4 {
  strings:
    $key_96c4 = { c1 b6 [2] f3 94 [2] f5 a1 [2] db a1 [2] e4 bd }

  condition:
    any of them
}