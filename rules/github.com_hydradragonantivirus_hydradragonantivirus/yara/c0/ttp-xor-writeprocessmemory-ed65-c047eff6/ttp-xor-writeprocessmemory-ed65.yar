rule TTP_XOR_WriteProcessMemory_ed65 {
  strings:
    $key_ed65 = { ba 17 [2] 88 35 [2] 8e 00 [2] a0 00 [2] 9f 1c }

  condition:
    any of them
}