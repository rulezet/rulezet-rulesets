rule TTP_XOR_WriteProcessMemory_8e4e {
  strings:
    $key_8e4e = { d9 3c [2] eb 1e [2] ed 2b [2] c3 2b [2] fc 37 }

  condition:
    any of them
}