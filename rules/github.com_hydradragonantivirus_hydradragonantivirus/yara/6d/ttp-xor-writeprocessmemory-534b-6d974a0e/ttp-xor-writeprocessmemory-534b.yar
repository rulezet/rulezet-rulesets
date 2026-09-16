rule TTP_XOR_WriteProcessMemory_534b {
  strings:
    $key_534b = { 04 39 [2] 36 1b [2] 30 2e [2] 1e 2e [2] 21 32 }

  condition:
    any of them
}