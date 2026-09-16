rule TTP_XOR_WriteProcessMemory_3487 {
  strings:
    $key_3487 = { 63 f5 [2] 51 d7 [2] 57 e2 [2] 79 e2 [2] 46 fe }

  condition:
    any of them
}