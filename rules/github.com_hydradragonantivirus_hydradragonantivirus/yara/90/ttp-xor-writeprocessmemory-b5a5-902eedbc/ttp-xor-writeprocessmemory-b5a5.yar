rule TTP_XOR_WriteProcessMemory_b5a5 {
  strings:
    $key_b5a5 = { e2 d7 [2] d0 f5 [2] d6 c0 [2] f8 c0 [2] c7 dc }

  condition:
    any of them
}