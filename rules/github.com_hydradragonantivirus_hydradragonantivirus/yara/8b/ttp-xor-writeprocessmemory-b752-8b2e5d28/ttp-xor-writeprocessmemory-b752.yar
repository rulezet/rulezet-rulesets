rule TTP_XOR_WriteProcessMemory_b752 {
  strings:
    $key_b752 = { e0 20 [2] d2 02 [2] d4 37 [2] fa 37 [2] c5 2b }

  condition:
    any of them
}