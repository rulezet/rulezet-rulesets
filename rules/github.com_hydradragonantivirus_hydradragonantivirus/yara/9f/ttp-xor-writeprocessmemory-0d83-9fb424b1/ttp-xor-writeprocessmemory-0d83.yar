rule TTP_XOR_WriteProcessMemory_0d83 {
  strings:
    $key_0d83 = { 5a f1 [2] 68 d3 [2] 6e e6 [2] 40 e6 [2] 7f fa }

  condition:
    any of them
}