rule TTP_XOR_WriteProcessMemory_ed22 {
  strings:
    $key_ed22 = { ba 50 [2] 88 72 [2] 8e 47 [2] a0 47 [2] 9f 5b }

  condition:
    any of them
}