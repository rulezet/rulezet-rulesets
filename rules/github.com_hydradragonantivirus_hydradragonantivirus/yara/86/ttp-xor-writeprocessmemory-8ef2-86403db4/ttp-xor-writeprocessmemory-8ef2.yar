rule TTP_XOR_WriteProcessMemory_8ef2 {
  strings:
    $key_8ef2 = { d9 80 [2] eb a2 [2] ed 97 [2] c3 97 [2] fc 8b }

  condition:
    any of them
}