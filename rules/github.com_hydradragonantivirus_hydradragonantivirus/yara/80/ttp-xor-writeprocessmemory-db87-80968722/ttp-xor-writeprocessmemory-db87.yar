rule TTP_XOR_WriteProcessMemory_db87 {
  strings:
    $key_db87 = { 8c f5 [2] be d7 [2] b8 e2 [2] 96 e2 [2] a9 fe }

  condition:
    any of them
}