rule TTP_XOR_WriteProcessMemory_8e49 {
  strings:
    $key_8e49 = { d9 3b [2] eb 19 [2] ed 2c [2] c3 2c [2] fc 30 }

  condition:
    any of them
}