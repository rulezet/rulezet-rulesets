rule TTP_XOR_WriteProcessMemory_653b {
  strings:
    $key_653b = { 32 49 [2] 00 6b [2] 06 5e [2] 28 5e [2] 17 42 }

  condition:
    any of them
}