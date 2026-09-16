rule TTP_XOR_WriteProcessMemory_ecfb {
  strings:
    $key_ecfb = { bb 89 [2] 89 ab [2] 8f 9e [2] a1 9e [2] 9e 82 }

  condition:
    any of them
}