rule TTP_XOR_WriteProcessMemory_b712 {
  strings:
    $key_b712 = { e0 60 [2] d2 42 [2] d4 77 [2] fa 77 [2] c5 6b }

  condition:
    any of them
}