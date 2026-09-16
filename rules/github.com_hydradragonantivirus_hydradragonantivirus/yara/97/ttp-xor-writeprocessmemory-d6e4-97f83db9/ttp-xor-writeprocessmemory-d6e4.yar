rule TTP_XOR_WriteProcessMemory_d6e4 {
  strings:
    $key_d6e4 = { 81 96 [2] b3 b4 [2] b5 81 [2] 9b 81 [2] a4 9d }

  condition:
    any of them
}