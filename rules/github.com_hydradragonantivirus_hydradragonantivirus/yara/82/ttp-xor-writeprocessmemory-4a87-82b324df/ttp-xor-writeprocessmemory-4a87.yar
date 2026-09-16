rule TTP_XOR_WriteProcessMemory_4a87 {
  strings:
    $key_4a87 = { 1d f5 [2] 2f d7 [2] 29 e2 [2] 07 e2 [2] 38 fe }

  condition:
    any of them
}