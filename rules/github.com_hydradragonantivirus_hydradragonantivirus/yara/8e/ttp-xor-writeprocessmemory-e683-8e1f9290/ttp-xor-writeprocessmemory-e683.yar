rule TTP_XOR_WriteProcessMemory_e683 {
  strings:
    $key_e683 = { b1 f1 [2] 83 d3 [2] 85 e6 [2] ab e6 [2] 94 fa }

  condition:
    any of them
}