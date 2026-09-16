rule TTP_XOR_WriteProcessMemory_b714 {
  strings:
    $key_b714 = { e0 66 [2] d2 44 [2] d4 71 [2] fa 71 [2] c5 6d }

  condition:
    any of them
}