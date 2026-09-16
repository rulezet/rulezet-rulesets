rule TTP_XOR_WriteProcessMemory_8e2e {
  strings:
    $key_8e2e = { d9 5c [2] eb 7e [2] ed 4b [2] c3 4b [2] fc 57 }

  condition:
    any of them
}