rule TTP_XOR_WriteProcessMemory_94a1 {
  strings:
    $key_94a1 = { c3 d3 [2] f1 f1 [2] f7 c4 [2] d9 c4 [2] e6 d8 }

  condition:
    any of them
}