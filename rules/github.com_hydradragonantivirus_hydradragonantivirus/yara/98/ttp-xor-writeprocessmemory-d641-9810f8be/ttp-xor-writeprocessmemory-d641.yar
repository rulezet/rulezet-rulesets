rule TTP_XOR_WriteProcessMemory_d641 {
  strings:
    $key_d641 = { 81 33 [2] b3 11 [2] b5 24 [2] 9b 24 [2] a4 38 }

  condition:
    any of them
}