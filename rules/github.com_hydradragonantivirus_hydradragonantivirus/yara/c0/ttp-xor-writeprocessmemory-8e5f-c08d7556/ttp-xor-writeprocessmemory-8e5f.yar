rule TTP_XOR_WriteProcessMemory_8e5f {
  strings:
    $key_8e5f = { d9 2d [2] eb 0f [2] ed 3a [2] c3 3a [2] fc 26 }

  condition:
    any of them
}