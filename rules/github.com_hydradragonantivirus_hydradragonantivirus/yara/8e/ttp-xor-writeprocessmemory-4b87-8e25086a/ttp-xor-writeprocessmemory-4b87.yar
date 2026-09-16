rule TTP_XOR_WriteProcessMemory_4b87 {
  strings:
    $key_4b87 = { 1c f5 [2] 2e d7 [2] 28 e2 [2] 06 e2 [2] 39 fe }

  condition:
    any of them
}