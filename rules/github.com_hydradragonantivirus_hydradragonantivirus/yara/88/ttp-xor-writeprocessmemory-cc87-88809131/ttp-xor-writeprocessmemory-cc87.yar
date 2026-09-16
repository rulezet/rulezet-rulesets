rule TTP_XOR_WriteProcessMemory_cc87 {
  strings:
    $key_cc87 = { 9b f5 [2] a9 d7 [2] af e2 [2] 81 e2 [2] be fe }

  condition:
    any of them
}