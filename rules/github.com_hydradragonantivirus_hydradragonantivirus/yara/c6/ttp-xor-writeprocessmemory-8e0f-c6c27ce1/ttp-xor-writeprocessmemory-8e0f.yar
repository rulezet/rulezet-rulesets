rule TTP_XOR_WriteProcessMemory_8e0f {
  strings:
    $key_8e0f = { d9 7d [2] eb 5f [2] ed 6a [2] c3 6a [2] fc 76 }

  condition:
    any of them
}