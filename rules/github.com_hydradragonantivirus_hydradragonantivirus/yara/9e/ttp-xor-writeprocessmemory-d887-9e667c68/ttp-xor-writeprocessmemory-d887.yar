rule TTP_XOR_WriteProcessMemory_d887 {
  strings:
    $key_d887 = { 8f f5 [2] bd d7 [2] bb e2 [2] 95 e2 [2] aa fe }

  condition:
    any of them
}