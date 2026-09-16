rule TTP_XOR_WriteProcessMemory_d5e4 {
  strings:
    $key_d5e4 = { 82 96 [2] b0 b4 [2] b6 81 [2] 98 81 [2] a7 9d }

  condition:
    any of them
}