rule TTP_XOR_WriteProcessMemory_8e30 {
  strings:
    $key_8e30 = { d9 42 [2] eb 60 [2] ed 55 [2] c3 55 [2] fc 49 }

  condition:
    any of them
}