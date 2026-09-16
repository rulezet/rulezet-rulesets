rule TTP_XOR_WriteProcessMemory_ed3c {
  strings:
    $key_ed3c = { ba 4e [2] 88 6c [2] 8e 59 [2] a0 59 [2] 9f 45 }

  condition:
    any of them
}