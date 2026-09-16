rule TTP_XOR_WriteProcessMemory_8e52 {
  strings:
    $key_8e52 = { d9 20 [2] eb 02 [2] ed 37 [2] c3 37 [2] fc 2b }

  condition:
    any of them
}