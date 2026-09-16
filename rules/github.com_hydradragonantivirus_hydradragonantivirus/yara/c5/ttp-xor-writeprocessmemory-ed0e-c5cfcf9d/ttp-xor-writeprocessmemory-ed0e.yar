rule TTP_XOR_WriteProcessMemory_ed0e {
  strings:
    $key_ed0e = { ba 7c [2] 88 5e [2] 8e 6b [2] a0 6b [2] 9f 77 }

  condition:
    any of them
}