rule TTP_XOR_WriteProcessMemory_d0e6 {
  strings:
    $key_d0e6 = { 87 94 [2] b5 b6 [2] b3 83 [2] 9d 83 [2] a2 9f }

  condition:
    any of them
}