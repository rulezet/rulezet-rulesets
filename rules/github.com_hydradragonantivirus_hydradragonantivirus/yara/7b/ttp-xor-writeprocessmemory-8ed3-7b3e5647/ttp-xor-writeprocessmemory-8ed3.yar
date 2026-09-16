rule TTP_XOR_WriteProcessMemory_8ed3 {
  strings:
    $key_8ed3 = { d9 a1 [2] eb 83 [2] ed b6 [2] c3 b6 [2] fc aa }

  condition:
    any of them
}