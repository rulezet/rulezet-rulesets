rule TTP_XOR_WriteProcessMemory_8e31 {
  strings:
    $key_8e31 = { d9 43 [2] eb 61 [2] ed 54 [2] c3 54 [2] fc 48 }

  condition:
    any of them
}