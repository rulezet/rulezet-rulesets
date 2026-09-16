rule TTP_XOR_WriteProcessMemory_273b {
  strings:
    $key_273b = { 70 49 [2] 42 6b [2] 44 5e [2] 6a 5e [2] 55 42 }

  condition:
    any of them
}