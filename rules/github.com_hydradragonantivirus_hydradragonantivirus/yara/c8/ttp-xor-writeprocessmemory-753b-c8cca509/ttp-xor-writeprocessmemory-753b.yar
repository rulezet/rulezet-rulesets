rule TTP_XOR_WriteProcessMemory_753b {
  strings:
    $key_753b = { 22 49 [2] 10 6b [2] 16 5e [2] 38 5e [2] 07 42 }

  condition:
    any of them
}