rule TTP_XOR_WriteProcessMemory_510b {
  strings:
    $key_510b = { 06 79 [2] 34 5b [2] 32 6e [2] 1c 6e [2] 23 72 }

  condition:
    any of them
}