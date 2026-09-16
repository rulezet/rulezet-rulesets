rule TTP_XOR_WriteProcessMemory_b585 {
  strings:
    $key_b585 = { e2 f7 [2] d0 d5 [2] d6 e0 [2] f8 e0 [2] c7 fc }

  condition:
    any of them
}