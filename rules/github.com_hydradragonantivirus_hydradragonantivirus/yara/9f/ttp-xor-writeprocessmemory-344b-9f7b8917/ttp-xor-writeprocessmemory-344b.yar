rule TTP_XOR_WriteProcessMemory_344b {
  strings:
    $key_344b = { 63 39 [2] 51 1b [2] 57 2e [2] 79 2e [2] 46 32 }

  condition:
    any of them
}