rule TTP_XOR_WriteProcessMemory_b485 {
  strings:
    $key_b485 = { e3 f7 [2] d1 d5 [2] d7 e0 [2] f9 e0 [2] c6 fc }

  condition:
    any of them
}