rule TTP_XOR_WriteProcessMemory_c5e4 {
  strings:
    $key_c5e4 = { 92 96 [2] a0 b4 [2] a6 81 [2] 88 81 [2] b7 9d }

  condition:
    any of them
}