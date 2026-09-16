rule TTP_XOR_WriteProcessMemory_d681 {
  strings:
    $key_d681 = { 81 f3 [2] b3 d1 [2] b5 e4 [2] 9b e4 [2] a4 f8 }

  condition:
    any of them
}