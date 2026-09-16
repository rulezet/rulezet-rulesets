rule TTP_XOR_WriteProcessMemory_5d83 {
  strings:
    $key_5d83 = { 0a f1 [2] 38 d3 [2] 3e e6 [2] 10 e6 [2] 2f fa }

  condition:
    any of them
}