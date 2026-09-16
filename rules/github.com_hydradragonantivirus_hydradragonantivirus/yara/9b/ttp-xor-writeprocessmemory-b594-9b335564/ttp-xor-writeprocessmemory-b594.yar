rule TTP_XOR_WriteProcessMemory_b594 {
  strings:
    $key_b594 = { e2 e6 [2] d0 c4 [2] d6 f1 [2] f8 f1 [2] c7 ed }

  condition:
    any of them
}