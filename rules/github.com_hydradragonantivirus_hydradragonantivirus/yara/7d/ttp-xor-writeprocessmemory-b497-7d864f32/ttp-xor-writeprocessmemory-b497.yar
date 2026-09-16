rule TTP_XOR_WriteProcessMemory_b497 {
  strings:
    $key_b497 = { e3 e5 [2] d1 c7 [2] d7 f2 [2] f9 f2 [2] c6 ee }

  condition:
    any of them
}