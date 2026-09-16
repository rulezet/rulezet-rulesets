rule TTP_XOR_WriteProcessMemory_d1d7 {
  strings:
    $key_d1d7 = { 86 a5 [2] b4 87 [2] b2 b2 [2] 9c b2 [2] a3 ae }

  condition:
    any of them
}