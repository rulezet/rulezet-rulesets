rule TTP_XOR_WriteProcessMemory_ede9 {
  strings:
    $key_ede9 = { ba 9b [2] 88 b9 [2] 8e 8c [2] a0 8c [2] 9f 90 }

  condition:
    any of them
}