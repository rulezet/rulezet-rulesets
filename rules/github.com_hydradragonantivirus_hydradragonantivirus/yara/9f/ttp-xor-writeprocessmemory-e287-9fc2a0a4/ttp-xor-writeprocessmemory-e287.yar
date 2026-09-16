rule TTP_XOR_WriteProcessMemory_e287 {
  strings:
    $key_e287 = { b5 f5 [2] 87 d7 [2] 81 e2 [2] af e2 [2] 90 fe }

  condition:
    any of them
}