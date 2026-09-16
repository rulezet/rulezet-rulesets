rule TTP_XOR_WriteProcessMemory_513b {
  strings:
    $key_513b = { 06 49 [2] 34 6b [2] 32 5e [2] 1c 5e [2] 23 42 }

  condition:
    any of them
}