rule TTP_XOR_WriteProcessMemory_4683 {
  strings:
    $key_4683 = { 11 f1 [2] 23 d3 [2] 25 e6 [2] 0b e6 [2] 34 fa }

  condition:
    any of them
}