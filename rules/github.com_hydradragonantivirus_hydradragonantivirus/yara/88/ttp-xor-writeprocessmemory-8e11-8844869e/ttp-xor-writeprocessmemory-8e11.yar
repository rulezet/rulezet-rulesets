rule TTP_XOR_WriteProcessMemory_8e11 {
  strings:
    $key_8e11 = { d9 63 [2] eb 41 [2] ed 74 [2] c3 74 [2] fc 68 }

  condition:
    any of them
}