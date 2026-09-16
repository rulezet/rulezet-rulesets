rule TTP_XOR_WriteProcessMemory_8e50 {
  strings:
    $key_8e50 = { d9 22 [2] eb 00 [2] ed 35 [2] c3 35 [2] fc 29 }

  condition:
    any of them
}