rule TTP_XOR_WriteProcessMemory_3083 {
  strings:
    $key_3083 = { 67 f1 [2] 55 d3 [2] 53 e6 [2] 7d e6 [2] 42 fa }

  condition:
    any of them
}