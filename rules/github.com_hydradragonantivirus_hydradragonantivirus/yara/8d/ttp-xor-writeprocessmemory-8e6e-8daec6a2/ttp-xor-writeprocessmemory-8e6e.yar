rule TTP_XOR_WriteProcessMemory_8e6e {
  strings:
    $key_8e6e = { d9 1c [2] eb 3e [2] ed 0b [2] c3 0b [2] fc 17 }

  condition:
    any of them
}