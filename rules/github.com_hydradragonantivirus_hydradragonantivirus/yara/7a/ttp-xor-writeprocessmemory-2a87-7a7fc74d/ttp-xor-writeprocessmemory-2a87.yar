rule TTP_XOR_WriteProcessMemory_2a87 {
  strings:
    $key_2a87 = { 7d f5 [2] 4f d7 [2] 49 e2 [2] 67 e2 [2] 58 fe }

  condition:
    any of them
}