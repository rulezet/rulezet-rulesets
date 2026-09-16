rule TTP_XOR_WriteProcessMemory_403b {
  strings:
    $key_403b = { 17 49 [2] 25 6b [2] 23 5e [2] 0d 5e [2] 32 42 }

  condition:
    any of them
}