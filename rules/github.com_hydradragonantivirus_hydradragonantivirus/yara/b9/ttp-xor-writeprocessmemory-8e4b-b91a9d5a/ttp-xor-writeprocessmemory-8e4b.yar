rule TTP_XOR_WriteProcessMemory_8e4b {
  strings:
    $key_8e4b = { d9 39 [2] eb 1b [2] ed 2e [2] c3 2e [2] fc 32 }

  condition:
    any of them
}