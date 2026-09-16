rule TTP_XOR_WriteProcessMemory_3a87 {
  strings:
    $key_3a87 = { 6d f5 [2] 5f d7 [2] 59 e2 [2] 77 e2 [2] 48 fe }

  condition:
    any of them
}