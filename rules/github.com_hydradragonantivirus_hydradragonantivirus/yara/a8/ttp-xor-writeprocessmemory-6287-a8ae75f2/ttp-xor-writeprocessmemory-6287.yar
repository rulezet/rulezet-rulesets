rule TTP_XOR_WriteProcessMemory_6287 {
  strings:
    $key_6287 = { 35 f5 [2] 07 d7 [2] 01 e2 [2] 2f e2 [2] 10 fe }

  condition:
    any of them
}