rule TTP_XOR_WriteProcessMemory_d7e4 {
  strings:
    $key_d7e4 = { 80 96 [2] b2 b4 [2] b4 81 [2] 9a 81 [2] a5 9d }

  condition:
    any of them
}