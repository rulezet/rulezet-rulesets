rule TTP_XOR_WriteProcessMemory_8e06 {
  strings:
    $key_8e06 = { d9 74 [2] eb 56 [2] ed 63 [2] c3 63 [2] fc 7f }

  condition:
    any of them
}