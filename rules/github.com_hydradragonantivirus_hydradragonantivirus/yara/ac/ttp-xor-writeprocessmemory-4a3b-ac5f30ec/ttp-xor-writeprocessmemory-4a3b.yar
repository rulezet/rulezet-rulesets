rule TTP_XOR_WriteProcessMemory_4a3b {
  strings:
    $key_4a3b = { 1d 49 [2] 2f 6b [2] 29 5e [2] 07 5e [2] 38 42 }

  condition:
    any of them
}