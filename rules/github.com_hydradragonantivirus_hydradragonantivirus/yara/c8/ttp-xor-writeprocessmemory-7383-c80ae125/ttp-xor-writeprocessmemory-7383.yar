rule TTP_XOR_WriteProcessMemory_7383 {
  strings:
    $key_7383 = { 24 f1 [2] 16 d3 [2] 10 e6 [2] 3e e6 [2] 01 fa }

  condition:
    any of them
}