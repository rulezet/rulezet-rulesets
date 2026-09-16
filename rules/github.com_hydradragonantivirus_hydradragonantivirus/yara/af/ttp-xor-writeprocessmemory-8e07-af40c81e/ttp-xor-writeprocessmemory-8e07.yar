rule TTP_XOR_WriteProcessMemory_8e07 {
  strings:
    $key_8e07 = { d9 75 [2] eb 57 [2] ed 62 [2] c3 62 [2] fc 7e }

  condition:
    any of them
}