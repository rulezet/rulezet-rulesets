rule TTP_XOR_WriteProcessMemory_2b87 {
  strings:
    $key_2b87 = { 7c f5 [2] 4e d7 [2] 48 e2 [2] 66 e2 [2] 59 fe }

  condition:
    any of them
}