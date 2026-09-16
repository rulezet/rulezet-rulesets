rule TTP_XOR_WriteProcessMemory_7487 {
  strings:
    $key_7487 = { 23 f5 [2] 11 d7 [2] 17 e2 [2] 39 e2 [2] 06 fe }

  condition:
    any of them
}