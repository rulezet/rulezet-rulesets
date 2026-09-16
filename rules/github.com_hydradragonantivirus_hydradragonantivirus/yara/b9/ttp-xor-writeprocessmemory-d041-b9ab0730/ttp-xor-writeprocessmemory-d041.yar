rule TTP_XOR_WriteProcessMemory_d041 {
  strings:
    $key_d041 = { 87 33 [2] b5 11 [2] b3 24 [2] 9d 24 [2] a2 38 }

  condition:
    any of them
}