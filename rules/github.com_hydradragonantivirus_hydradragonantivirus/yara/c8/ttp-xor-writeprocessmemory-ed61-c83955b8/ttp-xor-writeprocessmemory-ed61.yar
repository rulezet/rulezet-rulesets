rule TTP_XOR_WriteProcessMemory_ed61 {
  strings:
    $key_ed61 = { ba 13 [2] 88 31 [2] 8e 04 [2] a0 04 [2] 9f 18 }

  condition:
    any of them
}