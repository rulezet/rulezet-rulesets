rule TTP_XOR_WriteProcessMemory_5b87 {
  strings:
    $key_5b87 = { 0c f5 [2] 3e d7 [2] 38 e2 [2] 16 e2 [2] 29 fe }

  condition:
    any of them
}