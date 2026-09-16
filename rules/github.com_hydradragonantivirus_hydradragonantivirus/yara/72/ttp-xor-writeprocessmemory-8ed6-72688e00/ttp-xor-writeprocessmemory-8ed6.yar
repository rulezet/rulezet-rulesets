rule TTP_XOR_WriteProcessMemory_8ed6 {
  strings:
    $key_8ed6 = { d9 a4 [2] eb 86 [2] ed b3 [2] c3 b3 [2] fc af }

  condition:
    any of them
}