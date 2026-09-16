rule TTP_XOR_WriteProcessMemory_c306 {
  strings:
    $key_c306 = { 94 74 [2] a6 56 [2] a0 63 [2] 8e 63 [2] b1 7f }

  condition:
    any of them
}