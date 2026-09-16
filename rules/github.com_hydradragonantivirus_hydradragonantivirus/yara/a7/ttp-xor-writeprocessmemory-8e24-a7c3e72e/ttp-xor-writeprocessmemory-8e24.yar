rule TTP_XOR_WriteProcessMemory_8e24 {
  strings:
    $key_8e24 = { d9 56 [2] eb 74 [2] ed 41 [2] c3 41 [2] fc 5d }

  condition:
    any of them
}