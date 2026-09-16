rule TTP_XOR_WriteProcessMemory_1287 {
  strings:
    $key_1287 = { 45 f5 [2] 77 d7 [2] 71 e2 [2] 5f e2 [2] 60 fe }

  condition:
    any of them
}