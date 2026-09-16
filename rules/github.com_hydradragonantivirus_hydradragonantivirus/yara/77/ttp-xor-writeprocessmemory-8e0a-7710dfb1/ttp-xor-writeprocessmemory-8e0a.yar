rule TTP_XOR_WriteProcessMemory_8e0a {
  strings:
    $key_8e0a = { d9 78 [2] eb 5a [2] ed 6f [2] c3 6f [2] fc 73 }

  condition:
    any of them
}