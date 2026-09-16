rule TTP_XOR_WriteProcessMemory_dad7 {
  strings:
    $key_dad7 = { 8d a5 [2] bf 87 [2] b9 b2 [2] 97 b2 [2] a8 ae }

  condition:
    any of them
}