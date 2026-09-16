rule TTP_XOR_WriteProcessMemory_dad6 {
  strings:
    $key_dad6 = { 8d a4 [2] bf 86 [2] b9 b3 [2] 97 b3 [2] a8 af }

  condition:
    any of them
}