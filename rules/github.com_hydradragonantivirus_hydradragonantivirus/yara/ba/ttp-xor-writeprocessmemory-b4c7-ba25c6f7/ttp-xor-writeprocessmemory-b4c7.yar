rule TTP_XOR_WriteProcessMemory_b4c7 {
  strings:
    $key_b4c7 = { e3 b5 [2] d1 97 [2] d7 a2 [2] f9 a2 [2] c6 be }

  condition:
    any of them
}