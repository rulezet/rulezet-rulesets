rule TTP_XOR_WriteProcessMemory_2587 {
  strings:
    $key_2587 = { 72 f5 [2] 40 d7 [2] 46 e2 [2] 68 e2 [2] 57 fe }

  condition:
    any of them
}