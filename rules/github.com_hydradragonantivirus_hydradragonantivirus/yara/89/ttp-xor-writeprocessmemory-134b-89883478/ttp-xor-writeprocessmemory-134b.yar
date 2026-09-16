rule TTP_XOR_WriteProcessMemory_134b {
  strings:
    $key_134b = { 44 39 [2] 76 1b [2] 70 2e [2] 5e 2e [2] 61 32 }

  condition:
    any of them
}