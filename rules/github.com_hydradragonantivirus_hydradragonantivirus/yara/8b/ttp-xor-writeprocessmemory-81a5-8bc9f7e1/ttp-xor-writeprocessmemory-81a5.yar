rule TTP_XOR_WriteProcessMemory_81a5 {
  strings:
    $key_81a5 = { d6 d7 [2] e4 f5 [2] e2 c0 [2] cc c0 [2] f3 dc }

  condition:
    any of them
}