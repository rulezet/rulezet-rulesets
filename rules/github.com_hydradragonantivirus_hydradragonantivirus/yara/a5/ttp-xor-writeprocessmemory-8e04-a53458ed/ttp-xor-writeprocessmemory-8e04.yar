rule TTP_XOR_WriteProcessMemory_8e04 {
  strings:
    $key_8e04 = { d9 76 [2] eb 54 [2] ed 61 [2] c3 61 [2] fc 7d }

  condition:
    any of them
}