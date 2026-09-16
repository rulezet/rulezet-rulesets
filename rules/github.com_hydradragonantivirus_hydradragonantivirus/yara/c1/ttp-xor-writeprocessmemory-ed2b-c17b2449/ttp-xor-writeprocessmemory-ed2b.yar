rule TTP_XOR_WriteProcessMemory_ed2b {
  strings:
    $key_ed2b = { ba 59 [2] 88 7b [2] 8e 4e [2] a0 4e [2] 9f 52 }

  condition:
    any of them
}