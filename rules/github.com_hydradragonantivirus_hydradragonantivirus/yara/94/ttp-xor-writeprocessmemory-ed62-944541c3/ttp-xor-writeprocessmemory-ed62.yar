rule TTP_XOR_WriteProcessMemory_ed62 {
  strings:
    $key_ed62 = { ba 10 [2] 88 32 [2] 8e 07 [2] a0 07 [2] 9f 1b }

  condition:
    any of them
}