rule TTP_XOR_WriteProcessMemory_8e3a {
  strings:
    $key_8e3a = { d9 48 [2] eb 6a [2] ed 5f [2] c3 5f [2] fc 43 }

  condition:
    any of them
}