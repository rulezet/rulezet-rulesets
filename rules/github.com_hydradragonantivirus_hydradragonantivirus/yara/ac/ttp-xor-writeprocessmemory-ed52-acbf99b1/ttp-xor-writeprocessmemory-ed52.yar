rule TTP_XOR_WriteProcessMemory_ed52 {
  strings:
    $key_ed52 = { ba 20 [2] 88 02 [2] 8e 37 [2] a0 37 [2] 9f 2b }

  condition:
    any of them
}