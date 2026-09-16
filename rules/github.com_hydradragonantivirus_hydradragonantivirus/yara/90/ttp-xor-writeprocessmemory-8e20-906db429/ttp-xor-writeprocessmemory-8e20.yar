rule TTP_XOR_WriteProcessMemory_8e20 {
  strings:
    $key_8e20 = { d9 52 [2] eb 70 [2] ed 45 [2] c3 45 [2] fc 59 }

  condition:
    any of them
}