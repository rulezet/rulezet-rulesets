rule TTP_XOR_WriteProcessMemory_4383 {
  strings:
    $key_4383 = { 14 f1 [2] 26 d3 [2] 20 e6 [2] 0e e6 [2] 31 fa }

  condition:
    any of them
}