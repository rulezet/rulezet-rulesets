rule TTP_XOR_WriteProcessMemory_d5d7 {
  strings:
    $key_d5d7 = { 82 a5 [2] b0 87 [2] b6 b2 [2] 98 b2 [2] a7 ae }

  condition:
    any of them
}