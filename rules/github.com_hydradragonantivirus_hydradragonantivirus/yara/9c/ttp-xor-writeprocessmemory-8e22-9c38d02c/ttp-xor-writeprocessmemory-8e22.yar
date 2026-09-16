rule TTP_XOR_WriteProcessMemory_8e22 {
  strings:
    $key_8e22 = { d9 50 [2] eb 72 [2] ed 47 [2] c3 47 [2] fc 5b }

  condition:
    any of them
}