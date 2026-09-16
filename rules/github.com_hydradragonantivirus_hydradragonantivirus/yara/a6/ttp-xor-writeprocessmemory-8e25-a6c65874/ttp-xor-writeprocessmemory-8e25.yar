rule TTP_XOR_WriteProcessMemory_8e25 {
  strings:
    $key_8e25 = { d9 57 [2] eb 75 [2] ed 40 [2] c3 40 [2] fc 5c }

  condition:
    any of them
}