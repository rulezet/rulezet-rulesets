rule TTP_XOR_WriteProcessMemory_b5c7 {
  strings:
    $key_b5c7 = { e2 b5 [2] d0 97 [2] d6 a2 [2] f8 a2 [2] c7 be }

  condition:
    any of them
}