rule TTP_XOR_WriteProcessMemory_2683 {
  strings:
    $key_2683 = { 71 f1 [2] 43 d3 [2] 45 e6 [2] 6b e6 [2] 54 fa }

  condition:
    any of them
}