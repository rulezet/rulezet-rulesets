rule TTP_XOR_WriteProcessMemory_b4b4 {
  strings:
    $key_b4b4 = { e3 c6 [2] d1 e4 [2] d7 d1 [2] f9 d1 [2] c6 cd }

  condition:
    any of them
}