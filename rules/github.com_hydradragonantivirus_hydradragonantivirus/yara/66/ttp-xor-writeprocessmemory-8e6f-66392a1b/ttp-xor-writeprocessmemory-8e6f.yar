rule TTP_XOR_WriteProcessMemory_8e6f {
  strings:
    $key_8e6f = { d9 1d [2] eb 3f [2] ed 0a [2] c3 0a [2] fc 16 }

  condition:
    any of them
}