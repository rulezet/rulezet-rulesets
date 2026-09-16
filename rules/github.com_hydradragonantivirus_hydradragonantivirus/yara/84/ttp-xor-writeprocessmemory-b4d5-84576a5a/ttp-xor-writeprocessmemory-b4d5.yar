rule TTP_XOR_WriteProcessMemory_b4d5 {
  strings:
    $key_b4d5 = { e3 a7 [2] d1 85 [2] d7 b0 [2] f9 b0 [2] c6 ac }

  condition:
    any of them
}