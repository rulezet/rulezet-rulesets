rule TTP_XOR_WriteProcessMemory_2d83 {
  strings:
    $key_2d83 = { 7a f1 [2] 48 d3 [2] 4e e6 [2] 60 e6 [2] 5f fa }

  condition:
    any of them
}