rule TTP_XOR_WriteProcessMemory_8ed4 {
  strings:
    $key_8ed4 = { d9 a6 [2] eb 84 [2] ed b1 [2] c3 b1 [2] fc ad }

  condition:
    any of them
}