rule TTP_XOR_WriteProcessMemory_8e2b {
  strings:
    $key_8e2b = { d9 59 [2] eb 7b [2] ed 4e [2] c3 4e [2] fc 52 }

  condition:
    any of them
}