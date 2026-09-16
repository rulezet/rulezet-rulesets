rule TTP_XOR_WriteProcessMemory_8e21 {
  strings:
    $key_8e21 = { d9 53 [2] eb 71 [2] ed 44 [2] c3 44 [2] fc 58 }

  condition:
    any of them
}