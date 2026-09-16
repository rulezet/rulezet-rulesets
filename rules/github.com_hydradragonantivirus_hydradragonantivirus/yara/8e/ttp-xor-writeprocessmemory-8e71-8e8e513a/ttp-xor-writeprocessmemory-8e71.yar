rule TTP_XOR_WriteProcessMemory_8e71 {
  strings:
    $key_8e71 = { d9 03 [2] eb 21 [2] ed 14 [2] c3 14 [2] fc 08 }

  condition:
    any of them
}