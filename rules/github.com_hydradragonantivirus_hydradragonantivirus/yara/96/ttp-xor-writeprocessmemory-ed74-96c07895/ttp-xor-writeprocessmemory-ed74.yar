rule TTP_XOR_WriteProcessMemory_ed74 {
  strings:
    $key_ed74 = { ba 06 [2] 88 24 [2] 8e 11 [2] a0 11 [2] 9f 0d }

  condition:
    any of them
}