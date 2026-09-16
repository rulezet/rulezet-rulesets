rule TTP_XOR_WriteProcessMemory_8887 {
  strings:
    $key_8887 = { df f5 [2] ed d7 [2] eb e2 [2] c5 e2 [2] fa fe }

  condition:
    any of them
}