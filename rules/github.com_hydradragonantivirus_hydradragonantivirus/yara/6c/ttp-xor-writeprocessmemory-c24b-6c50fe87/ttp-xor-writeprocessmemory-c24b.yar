rule TTP_XOR_WriteProcessMemory_c24b {
  strings:
    $key_c24b = { 95 39 [2] a7 1b [2] a1 2e [2] 8f 2e [2] b0 32 }

  condition:
    any of them
}