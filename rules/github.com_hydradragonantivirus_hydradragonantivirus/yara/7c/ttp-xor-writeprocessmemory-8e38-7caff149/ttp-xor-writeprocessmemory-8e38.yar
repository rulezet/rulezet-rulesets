rule TTP_XOR_WriteProcessMemory_8e38 {
  strings:
    $key_8e38 = { d9 4a [2] eb 68 [2] ed 5d [2] c3 5d [2] fc 41 }

  condition:
    any of them
}