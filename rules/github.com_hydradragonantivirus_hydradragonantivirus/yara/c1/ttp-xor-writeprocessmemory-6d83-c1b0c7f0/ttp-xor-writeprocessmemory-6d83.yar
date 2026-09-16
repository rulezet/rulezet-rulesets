rule TTP_XOR_WriteProcessMemory_6d83 {
  strings:
    $key_6d83 = { 3a f1 [2] 08 d3 [2] 0e e6 [2] 20 e6 [2] 1f fa }

  condition:
    any of them
}