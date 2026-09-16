rule TTP_XOR_WriteProcessMemory_dad4 {
  strings:
    $key_dad4 = { 8d a6 [2] bf 84 [2] b9 b1 [2] 97 b1 [2] a8 ad }

  condition:
    any of them
}