rule TTP_XOR_WriteProcessMemory_ed27 {
  strings:
    $key_ed27 = { ba 55 [2] 88 77 [2] 8e 42 [2] a0 42 [2] 9f 5e }

  condition:
    any of them
}