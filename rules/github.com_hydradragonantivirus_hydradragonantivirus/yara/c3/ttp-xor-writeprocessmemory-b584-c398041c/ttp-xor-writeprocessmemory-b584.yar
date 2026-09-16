rule TTP_XOR_WriteProcessMemory_b584 {
  strings:
    $key_b584 = { e2 f6 [2] d0 d4 [2] d6 e1 [2] f8 e1 [2] c7 fd }

  condition:
    any of them
}