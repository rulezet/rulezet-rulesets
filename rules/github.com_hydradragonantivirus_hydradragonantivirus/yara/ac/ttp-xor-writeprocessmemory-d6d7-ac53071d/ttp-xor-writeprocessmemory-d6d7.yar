rule TTP_XOR_WriteProcessMemory_d6d7 {
  strings:
    $key_d6d7 = { 81 a5 [2] b3 87 [2] b5 b2 [2] 9b b2 [2] a4 ae }

  condition:
    any of them
}