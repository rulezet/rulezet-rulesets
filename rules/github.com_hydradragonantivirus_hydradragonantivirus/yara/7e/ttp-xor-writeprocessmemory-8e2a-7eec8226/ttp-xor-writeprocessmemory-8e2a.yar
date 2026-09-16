rule TTP_XOR_WriteProcessMemory_8e2a {
  strings:
    $key_8e2a = { d9 58 [2] eb 7a [2] ed 4f [2] c3 4f [2] fc 53 }

  condition:
    any of them
}