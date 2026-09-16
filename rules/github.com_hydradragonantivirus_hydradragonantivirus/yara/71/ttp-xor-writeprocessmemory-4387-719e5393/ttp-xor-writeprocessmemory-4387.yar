rule TTP_XOR_WriteProcessMemory_4387 {
  strings:
    $key_4387 = { 14 f5 [2] 26 d7 [2] 20 e2 [2] 0e e2 [2] 31 fe }

  condition:
    any of them
}