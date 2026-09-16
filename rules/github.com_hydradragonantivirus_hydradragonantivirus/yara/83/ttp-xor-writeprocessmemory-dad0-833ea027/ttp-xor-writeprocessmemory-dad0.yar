rule TTP_XOR_WriteProcessMemory_dad0 {
  strings:
    $key_dad0 = { 8d a2 [2] bf 80 [2] b9 b5 [2] 97 b5 [2] a8 a9 }

  condition:
    any of them
}