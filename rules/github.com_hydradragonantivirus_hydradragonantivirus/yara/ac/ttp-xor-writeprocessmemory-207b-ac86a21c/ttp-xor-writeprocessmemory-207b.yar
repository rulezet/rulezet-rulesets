rule TTP_XOR_WriteProcessMemory_207b {
  strings:
    $key_207b = { 77 09 [2] 45 2b [2] 43 1e [2] 6d 1e [2] 52 02 }

  condition:
    any of them
}