rule TTP_XOR_WriteProcessMemory_8e42 {
  strings:
    $key_8e42 = { d9 30 [2] eb 12 [2] ed 27 [2] c3 27 [2] fc 3b }

  condition:
    any of them
}