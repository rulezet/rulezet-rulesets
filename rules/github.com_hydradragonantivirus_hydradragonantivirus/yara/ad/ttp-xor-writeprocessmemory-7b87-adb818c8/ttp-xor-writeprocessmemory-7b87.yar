rule TTP_XOR_WriteProcessMemory_7b87 {
  strings:
    $key_7b87 = { 2c f5 [2] 1e d7 [2] 18 e2 [2] 36 e2 [2] 09 fe }

  condition:
    any of them
}