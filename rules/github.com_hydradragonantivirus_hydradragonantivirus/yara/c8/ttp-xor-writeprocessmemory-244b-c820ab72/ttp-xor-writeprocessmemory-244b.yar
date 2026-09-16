rule TTP_XOR_WriteProcessMemory_244b {
  strings:
    $key_244b = { 73 39 [2] 41 1b [2] 47 2e [2] 69 2e [2] 56 32 }

  condition:
    any of them
}