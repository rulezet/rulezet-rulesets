rule TTP_XOR_WriteProcessMemory_8e23 {
  strings:
    $key_8e23 = { d9 51 [2] eb 73 [2] ed 46 [2] c3 46 [2] fc 5a }

  condition:
    any of them
}