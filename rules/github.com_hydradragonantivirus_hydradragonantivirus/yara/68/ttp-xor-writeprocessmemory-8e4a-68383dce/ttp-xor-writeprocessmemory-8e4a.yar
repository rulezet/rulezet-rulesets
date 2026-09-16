rule TTP_XOR_WriteProcessMemory_8e4a {
  strings:
    $key_8e4a = { d9 38 [2] eb 1a [2] ed 2f [2] c3 2f [2] fc 33 }

  condition:
    any of them
}