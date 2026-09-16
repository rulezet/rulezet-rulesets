rule TTP_XOR_WriteProcessMemory_7187 {
  strings:
    $key_7187 = { 26 f5 [2] 14 d7 [2] 12 e2 [2] 3c e2 [2] 03 fe }

  condition:
    any of them
}