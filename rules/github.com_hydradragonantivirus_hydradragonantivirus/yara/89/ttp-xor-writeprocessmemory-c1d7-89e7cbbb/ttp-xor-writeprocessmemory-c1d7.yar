rule TTP_XOR_WriteProcessMemory_c1d7 {
  strings:
    $key_c1d7 = { 96 a5 [2] a4 87 [2] a2 b2 [2] 8c b2 [2] b3 ae }

  condition:
    any of them
}