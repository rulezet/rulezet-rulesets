rule TTP_XOR_WriteProcessMemory_8ed1 {
  strings:
    $key_8ed1 = { d9 a3 [2] eb 81 [2] ed b4 [2] c3 b4 [2] fc a8 }

  condition:
    any of them
}