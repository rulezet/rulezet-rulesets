rule TTP_XOR_WriteProcessMemory_ed7e {
  strings:
    $key_ed7e = { ba 0c [2] 88 2e [2] 8e 1b [2] a0 1b [2] 9f 07 }

  condition:
    any of them
}