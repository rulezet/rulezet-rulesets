rule TTP_XOR_WriteProcessMemory_0a87 {
  strings:
    $key_0a87 = { 5d f5 [2] 6f d7 [2] 69 e2 [2] 47 e2 [2] 78 fe }

  condition:
    any of them
}