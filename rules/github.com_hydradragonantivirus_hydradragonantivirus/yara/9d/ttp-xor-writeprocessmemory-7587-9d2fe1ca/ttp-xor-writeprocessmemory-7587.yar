rule TTP_XOR_WriteProcessMemory_7587 {
  strings:
    $key_7587 = { 22 f5 [2] 10 d7 [2] 16 e2 [2] 38 e2 [2] 07 fe }

  condition:
    any of them
}