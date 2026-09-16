rule TTP_XOR_WriteProcessMemory_8e1a {
  strings:
    $key_8e1a = { d9 68 [2] eb 4a [2] ed 7f [2] c3 7f [2] fc 63 }

  condition:
    any of them
}