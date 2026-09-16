rule TTP_XOR_WriteProcessMemory_d616 {
  strings:
    $key_d616 = { 81 64 [2] b3 46 [2] b5 73 [2] 9b 73 [2] a4 6f }

  condition:
    any of them
}