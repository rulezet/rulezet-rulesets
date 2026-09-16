rule TTP_XOR_WriteProcessMemory_483b {
  strings:
    $key_483b = { 1f 49 [2] 2d 6b [2] 2b 5e [2] 05 5e [2] 3a 42 }

  condition:
    any of them
}