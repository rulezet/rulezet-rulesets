rule TTP_XOR_WriteProcessMemory_0d87 {
  strings:
    $key_0d87 = { 5a f5 [2] 68 d7 [2] 6e e2 [2] 40 e2 [2] 7f fe }

  condition:
    any of them
}