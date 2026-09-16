rule TTP_XOR_WriteProcessMemory_83a5 {
  strings:
    $key_83a5 = { d4 d7 [2] e6 f5 [2] e0 c0 [2] ce c0 [2] f1 dc }

  condition:
    any of them
}