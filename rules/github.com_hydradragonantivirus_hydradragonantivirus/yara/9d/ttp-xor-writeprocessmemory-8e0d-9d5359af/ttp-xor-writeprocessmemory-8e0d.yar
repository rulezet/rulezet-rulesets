rule TTP_XOR_WriteProcessMemory_8e0d {
  strings:
    $key_8e0d = { d9 7f [2] eb 5d [2] ed 68 [2] c3 68 [2] fc 74 }

  condition:
    any of them
}