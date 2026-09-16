rule TTP_XOR_WriteProcessMemory_b5b4 {
  strings:
    $key_b5b4 = { e2 c6 [2] d0 e4 [2] d6 d1 [2] f8 d1 [2] c7 cd }

  condition:
    any of them
}