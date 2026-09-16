rule TTP_XOR_WriteProcessMemory_7683 {
  strings:
    $key_7683 = { 21 f1 [2] 13 d3 [2] 15 e6 [2] 3b e6 [2] 04 fa }

  condition:
    any of them
}