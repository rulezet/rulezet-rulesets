rule TTP_XOR_WriteProcessMemory_ed54 {
  strings:
    $key_ed54 = { ba 26 [2] 88 04 [2] 8e 31 [2] a0 31 [2] 9f 2d }

  condition:
    any of them
}