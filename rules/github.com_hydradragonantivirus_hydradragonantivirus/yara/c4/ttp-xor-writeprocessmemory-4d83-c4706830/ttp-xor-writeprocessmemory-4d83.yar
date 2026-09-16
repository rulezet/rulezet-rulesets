rule TTP_XOR_WriteProcessMemory_4d83 {
  strings:
    $key_4d83 = { 1a f1 [2] 28 d3 [2] 2e e6 [2] 00 e6 [2] 3f fa }

  condition:
    any of them
}