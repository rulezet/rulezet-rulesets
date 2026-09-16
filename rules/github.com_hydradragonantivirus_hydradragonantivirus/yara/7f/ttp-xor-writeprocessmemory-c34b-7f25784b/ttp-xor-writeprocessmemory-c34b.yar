rule TTP_XOR_WriteProcessMemory_c34b {
  strings:
    $key_c34b = { 94 39 [2] a6 1b [2] a0 2e [2] 8e 2e [2] b1 32 }

  condition:
    any of them
}