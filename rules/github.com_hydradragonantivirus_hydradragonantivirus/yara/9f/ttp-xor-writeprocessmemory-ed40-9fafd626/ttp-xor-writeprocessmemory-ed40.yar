rule TTP_XOR_WriteProcessMemory_ed40 {
  strings:
    $key_ed40 = { ba 32 [2] 88 10 [2] 8e 25 [2] a0 25 [2] 9f 39 }

  condition:
    any of them
}