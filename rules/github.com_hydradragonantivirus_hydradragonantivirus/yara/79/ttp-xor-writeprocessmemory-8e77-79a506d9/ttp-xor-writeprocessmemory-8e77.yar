rule TTP_XOR_WriteProcessMemory_8e77 {
  strings:
    $key_8e77 = { d9 05 [2] eb 27 [2] ed 12 [2] c3 12 [2] fc 0e }

  condition:
    any of them
}