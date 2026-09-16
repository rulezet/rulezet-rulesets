rule TTP_XOR_WriteProcessMemory_876b {
  strings:
    $key_876b = { d0 19 [2] e2 3b [2] e4 0e [2] ca 0e [2] f5 12 }

  condition:
    any of them
}