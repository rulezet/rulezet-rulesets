rule TTP_XOR_WriteProcessMemory_8e60 {
  strings:
    $key_8e60 = { d9 12 [2] eb 30 [2] ed 05 [2] c3 05 [2] fc 19 }

  condition:
    any of them
}