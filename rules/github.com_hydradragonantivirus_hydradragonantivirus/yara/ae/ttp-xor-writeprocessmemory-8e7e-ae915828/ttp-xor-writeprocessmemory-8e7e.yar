rule TTP_XOR_WriteProcessMemory_8e7e {
  strings:
    $key_8e7e = { d9 0c [2] eb 2e [2] ed 1b [2] c3 1b [2] fc 07 }

  condition:
    any of them
}