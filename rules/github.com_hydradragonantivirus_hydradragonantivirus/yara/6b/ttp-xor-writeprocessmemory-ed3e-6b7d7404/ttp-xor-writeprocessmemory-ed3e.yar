rule TTP_XOR_WriteProcessMemory_ed3e {
  strings:
    $key_ed3e = { ba 4c [2] 88 6e [2] 8e 5b [2] a0 5b [2] 9f 47 }

  condition:
    any of them
}