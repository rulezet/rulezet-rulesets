rule TTP_XOR_WriteProcessMemory_b7a2 {
  strings:
    $key_b7a2 = { e0 d0 [2] d2 f2 [2] d4 c7 [2] fa c7 [2] c5 db }

  condition:
    any of them
}