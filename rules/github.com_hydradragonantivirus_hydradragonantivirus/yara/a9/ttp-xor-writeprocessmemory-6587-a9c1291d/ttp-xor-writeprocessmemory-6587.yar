rule TTP_XOR_WriteProcessMemory_6587 {
  strings:
    $key_6587 = { 32 f5 [2] 00 d7 [2] 06 e2 [2] 28 e2 [2] 17 fe }

  condition:
    any of them
}