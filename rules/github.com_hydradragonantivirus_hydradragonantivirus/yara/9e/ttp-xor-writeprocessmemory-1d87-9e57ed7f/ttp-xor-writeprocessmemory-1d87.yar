rule TTP_XOR_WriteProcessMemory_1d87 {
  strings:
    $key_1d87 = { 4a f5 [2] 78 d7 [2] 7e e2 [2] 50 e2 [2] 6f fe }

  condition:
    any of them
}