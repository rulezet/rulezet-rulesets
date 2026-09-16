rule TTP_XOR_WriteProcessMemory_8e10 {
  strings:
    $key_8e10 = { d9 62 [2] eb 40 [2] ed 75 [2] c3 75 [2] fc 69 }

  condition:
    any of them
}