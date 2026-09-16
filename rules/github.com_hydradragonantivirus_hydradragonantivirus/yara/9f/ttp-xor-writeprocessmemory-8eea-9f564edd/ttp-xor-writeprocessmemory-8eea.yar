rule TTP_XOR_WriteProcessMemory_8eea {
  strings:
    $key_8eea = { d9 98 [2] eb ba [2] ed 8f [2] c3 8f [2] fc 93 }

  condition:
    any of them
}