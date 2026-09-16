rule TTP_XOR_WriteProcessMemory_ed60 {
  strings:
    $key_ed60 = { ba 12 [2] 88 30 [2] 8e 05 [2] a0 05 [2] 9f 19 }

  condition:
    any of them
}