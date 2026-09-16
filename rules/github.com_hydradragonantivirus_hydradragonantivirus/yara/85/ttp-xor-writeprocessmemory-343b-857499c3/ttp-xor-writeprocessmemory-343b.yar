rule TTP_XOR_WriteProcessMemory_343b {
  strings:
    $key_343b = { 63 49 [2] 51 6b [2] 57 5e [2] 79 5e [2] 46 42 }

  condition:
    any of them
}