rule TTP_XOR_WriteProcessMemory_6b87 {
  strings:
    $key_6b87 = { 3c f5 [2] 0e d7 [2] 08 e2 [2] 26 e2 [2] 19 fe }

  condition:
    any of them
}