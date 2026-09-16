rule TTP_XOR_WriteProcessMemory_5787 {
  strings:
    $key_5787 = { 00 f5 [2] 32 d7 [2] 34 e2 [2] 1a e2 [2] 25 fe }

  condition:
    any of them
}