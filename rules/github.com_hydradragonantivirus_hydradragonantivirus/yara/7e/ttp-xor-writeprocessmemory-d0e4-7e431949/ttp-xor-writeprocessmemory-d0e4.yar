rule TTP_XOR_WriteProcessMemory_d0e4 {
  strings:
    $key_d0e4 = { 87 96 [2] b5 b4 [2] b3 81 [2] 9d 81 [2] a2 9d }

  condition:
    any of them
}