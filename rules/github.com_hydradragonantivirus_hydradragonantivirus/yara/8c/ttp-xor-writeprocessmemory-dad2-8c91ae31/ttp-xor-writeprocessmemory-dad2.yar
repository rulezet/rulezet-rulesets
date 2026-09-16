rule TTP_XOR_WriteProcessMemory_dad2 {
  strings:
    $key_dad2 = { 8d a0 [2] bf 82 [2] b9 b7 [2] 97 b7 [2] a8 ab }

  condition:
    any of them
}