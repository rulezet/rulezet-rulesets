rule TTP_XOR_WriteProcessMemory_ed1b {
  strings:
    $key_ed1b = { ba 69 [2] 88 4b [2] 8e 7e [2] a0 7e [2] 9f 62 }

  condition:
    any of them
}