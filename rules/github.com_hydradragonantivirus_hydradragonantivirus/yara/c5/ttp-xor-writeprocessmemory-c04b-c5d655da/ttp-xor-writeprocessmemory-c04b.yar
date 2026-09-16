rule TTP_XOR_WriteProcessMemory_c04b {
  strings:
    $key_c04b = { 97 39 [2] a5 1b [2] a3 2e [2] 8d 2e [2] b2 32 }

  condition:
    any of them
}