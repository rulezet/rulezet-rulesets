rule TTP_XOR_WriteProcessMemory_6d87 {
  strings:
    $key_6d87 = { 3a f5 [2] 08 d7 [2] 0e e2 [2] 20 e2 [2] 1f fe }

  condition:
    any of them
}