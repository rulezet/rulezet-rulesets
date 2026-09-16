rule TTP_XOR_WriteProcessMemory_8e13 {
  strings:
    $key_8e13 = { d9 61 [2] eb 43 [2] ed 76 [2] c3 76 [2] fc 6a }

  condition:
    any of them
}