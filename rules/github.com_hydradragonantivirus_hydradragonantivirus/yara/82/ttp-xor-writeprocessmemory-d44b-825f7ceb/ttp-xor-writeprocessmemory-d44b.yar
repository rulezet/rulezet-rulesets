rule TTP_XOR_WriteProcessMemory_d44b {
  strings:
    $key_d44b = { 83 39 [2] b1 1b [2] b7 2e [2] 99 2e [2] a6 32 }

  condition:
    any of them
}