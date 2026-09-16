rule TTP_XOR_WriteProcessMemory_7dfb {
  strings:
    $key_7dfb = { 2a 89 [2] 18 ab [2] 1e 9e [2] 30 9e [2] 0f 82 }

  condition:
    any of them
}