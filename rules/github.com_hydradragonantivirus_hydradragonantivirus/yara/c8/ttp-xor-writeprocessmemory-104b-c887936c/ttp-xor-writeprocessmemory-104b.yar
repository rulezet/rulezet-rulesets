rule TTP_XOR_WriteProcessMemory_104b {
  strings:
    $key_104b = { 47 39 [2] 75 1b [2] 73 2e [2] 5d 2e [2] 62 32 }

  condition:
    any of them
}