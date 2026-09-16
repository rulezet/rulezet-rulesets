rule TTP_XOR_WriteProcessMemory_8e33 {
  strings:
    $key_8e33 = { d9 41 [2] eb 63 [2] ed 56 [2] c3 56 [2] fc 4a }

  condition:
    any of them
}