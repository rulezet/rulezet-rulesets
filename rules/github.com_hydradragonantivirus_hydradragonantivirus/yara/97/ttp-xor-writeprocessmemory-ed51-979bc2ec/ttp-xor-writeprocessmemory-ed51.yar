rule TTP_XOR_WriteProcessMemory_ed51 {
  strings:
    $key_ed51 = { ba 23 [2] 88 01 [2] 8e 34 [2] a0 34 [2] 9f 28 }

  condition:
    any of them
}