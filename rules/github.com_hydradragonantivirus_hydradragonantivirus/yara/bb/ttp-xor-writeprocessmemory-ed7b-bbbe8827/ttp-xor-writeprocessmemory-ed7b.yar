rule TTP_XOR_WriteProcessMemory_ed7b {
  strings:
    $key_ed7b = { ba 09 [2] 88 2b [2] 8e 1e [2] a0 1e [2] 9f 02 }

  condition:
    any of them
}