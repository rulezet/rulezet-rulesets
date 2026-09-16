rule TTP_XOR_WriteProcessMemory_6487 {
  strings:
    $key_6487 = { 33 f5 [2] 01 d7 [2] 07 e2 [2] 29 e2 [2] 16 fe }

  condition:
    any of them
}