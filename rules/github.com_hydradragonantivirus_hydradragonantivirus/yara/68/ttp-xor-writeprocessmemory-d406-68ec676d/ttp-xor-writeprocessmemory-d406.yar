rule TTP_XOR_WriteProcessMemory_d406 {
  strings:
    $key_d406 = { 83 74 [2] b1 56 [2] b7 63 [2] 99 63 [2] a6 7f }

  condition:
    any of them
}