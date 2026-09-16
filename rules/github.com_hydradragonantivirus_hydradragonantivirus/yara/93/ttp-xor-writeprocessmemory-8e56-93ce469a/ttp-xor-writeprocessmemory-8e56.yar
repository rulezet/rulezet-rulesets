rule TTP_XOR_WriteProcessMemory_8e56 {
  strings:
    $key_8e56 = { d9 24 [2] eb 06 [2] ed 33 [2] c3 33 [2] fc 2f }

  condition:
    any of them
}