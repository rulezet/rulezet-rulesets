rule TTP_XOR_WriteProcessMemory_144b {
  strings:
    $key_144b = { 43 39 [2] 71 1b [2] 77 2e [2] 59 2e [2] 66 32 }

  condition:
    any of them
}