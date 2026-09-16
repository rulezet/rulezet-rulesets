rule TTP_XOR_WriteProcessMemory_8e74 {
  strings:
    $key_8e74 = { d9 06 [2] eb 24 [2] ed 11 [2] c3 11 [2] fc 0d }

  condition:
    any of them
}