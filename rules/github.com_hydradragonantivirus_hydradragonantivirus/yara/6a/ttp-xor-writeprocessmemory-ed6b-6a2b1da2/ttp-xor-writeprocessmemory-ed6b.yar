rule TTP_XOR_WriteProcessMemory_ed6b {
  strings:
    $key_ed6b = { ba 19 [2] 88 3b [2] 8e 0e [2] a0 0e [2] 9f 12 }

  condition:
    any of them
}