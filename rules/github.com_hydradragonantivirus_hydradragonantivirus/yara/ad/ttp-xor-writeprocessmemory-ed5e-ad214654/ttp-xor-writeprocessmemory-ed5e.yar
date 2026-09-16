rule TTP_XOR_WriteProcessMemory_ed5e {
  strings:
    $key_ed5e = { ba 2c [2] 88 0e [2] 8e 3b [2] a0 3b [2] 9f 27 }

  condition:
    any of them
}