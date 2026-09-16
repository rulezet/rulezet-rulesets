rule TTP_XOR_WriteProcessMemory_d506 {
  strings:
    $key_d506 = { 82 74 [2] b0 56 [2] b6 63 [2] 98 63 [2] a7 7f }

  condition:
    any of them
}