rule TTP_XOR_WriteProcessMemory_d342 {
  strings:
    $key_d342 = { 84 30 [2] b6 12 [2] b0 27 [2] 9e 27 [2] a1 3b }

  condition:
    any of them
}