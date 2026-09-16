rule TTP_XOR_WriteProcessMemory_d34b {
  strings:
    $key_d34b = { 84 39 [2] b6 1b [2] b0 2e [2] 9e 2e [2] a1 32 }

  condition:
    any of them
}