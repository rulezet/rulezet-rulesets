rule TTP_XOR_WriteProcessMemory_8e12 {
  strings:
    $key_8e12 = { d9 60 [2] eb 42 [2] ed 77 [2] c3 77 [2] fc 6b }

  condition:
    any of them
}