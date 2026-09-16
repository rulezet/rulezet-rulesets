rule TTP_XOR_WriteProcessMemory_d685 {
  strings:
    $key_d685 = { 81 f7 [2] b3 d5 [2] b5 e0 [2] 9b e0 [2] a4 fc }

  condition:
    any of them
}