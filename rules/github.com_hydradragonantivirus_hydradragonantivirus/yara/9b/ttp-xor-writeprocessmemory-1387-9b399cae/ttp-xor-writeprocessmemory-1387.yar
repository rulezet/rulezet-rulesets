rule TTP_XOR_WriteProcessMemory_1387 {
  strings:
    $key_1387 = { 44 f5 [2] 76 d7 [2] 70 e2 [2] 5e e2 [2] 61 fe }

  condition:
    any of them
}