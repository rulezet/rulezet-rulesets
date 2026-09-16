rule TTP_XOR_WriteProcessMemory_d1dc {
  strings:
    $key_d1dc = { 86 ae [2] b4 8c [2] b2 b9 [2] 9c b9 [2] a3 a5 }

  condition:
    any of them
}