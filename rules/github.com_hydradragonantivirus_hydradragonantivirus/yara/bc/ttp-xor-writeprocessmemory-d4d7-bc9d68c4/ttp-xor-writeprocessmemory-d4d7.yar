rule TTP_XOR_WriteProcessMemory_d4d7 {
  strings:
    $key_d4d7 = { 83 a5 [2] b1 87 [2] b7 b2 [2] 99 b2 [2] a6 ae }

  condition:
    any of them
}