rule TTP_XOR_WriteProcessMemory_d016 {
  strings:
    $key_d016 = { 87 64 [2] b5 46 [2] b3 73 [2] 9d 73 [2] a2 6f }

  condition:
    any of them
}