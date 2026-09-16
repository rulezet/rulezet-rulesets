rule TTP_XOR_WriteProcessMemory_b492 {
  strings:
    $key_b492 = { e3 e0 [2] d1 c2 [2] d7 f7 [2] f9 f7 [2] c6 eb }

  condition:
    any of them
}