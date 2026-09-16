rule TTP_XOR_WriteProcessMemory_8597 {
  strings:
    $key_8597 = { d2 e5 [2] e0 c7 [2] e6 f2 [2] c8 f2 [2] f7 ee }

  condition:
    any of them
}