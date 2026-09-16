rule TTP_XOR_WriteProcessMemory_b742 {
  strings:
    $key_b742 = { e0 30 [2] d2 12 [2] d4 27 [2] fa 27 [2] c5 3b }

  condition:
    any of them
}