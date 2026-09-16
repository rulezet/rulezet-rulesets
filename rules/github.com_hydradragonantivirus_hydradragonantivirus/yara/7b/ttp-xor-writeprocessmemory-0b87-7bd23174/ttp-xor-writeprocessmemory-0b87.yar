rule TTP_XOR_WriteProcessMemory_0b87 {
  strings:
    $key_0b87 = { 5c f5 [2] 6e d7 [2] 68 e2 [2] 46 e2 [2] 79 fe }

  condition:
    any of them
}