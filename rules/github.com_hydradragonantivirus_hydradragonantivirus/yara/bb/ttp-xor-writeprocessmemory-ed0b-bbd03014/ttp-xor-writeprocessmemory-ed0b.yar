rule TTP_XOR_WriteProcessMemory_ed0b {
  strings:
    $key_ed0b = { ba 79 [2] 88 5b [2] 8e 6e [2] a0 6e [2] 9f 72 }

  condition:
    any of them
}