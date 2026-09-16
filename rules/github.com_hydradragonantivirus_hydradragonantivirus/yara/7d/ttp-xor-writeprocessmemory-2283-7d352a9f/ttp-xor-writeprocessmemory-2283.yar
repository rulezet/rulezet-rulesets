rule TTP_XOR_WriteProcessMemory_2283 {
  strings:
    $key_2283 = { 75 f1 [2] 47 d3 [2] 41 e6 [2] 6f e6 [2] 50 fa }

  condition:
    any of them
}