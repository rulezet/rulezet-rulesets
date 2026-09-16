rule TTP_XOR_WriteProcessMemory_ed29 {
  strings:
    $key_ed29 = { ba 5b [2] 88 79 [2] 8e 4c [2] a0 4c [2] 9f 50 }

  condition:
    any of them
}