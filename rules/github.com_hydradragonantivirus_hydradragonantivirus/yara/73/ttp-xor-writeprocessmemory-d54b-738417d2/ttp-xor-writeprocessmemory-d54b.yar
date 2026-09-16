rule TTP_XOR_WriteProcessMemory_d54b {
  strings:
    $key_d54b = { 82 39 [2] b0 1b [2] b6 2e [2] 98 2e [2] a7 32 }

  condition:
    any of them
}