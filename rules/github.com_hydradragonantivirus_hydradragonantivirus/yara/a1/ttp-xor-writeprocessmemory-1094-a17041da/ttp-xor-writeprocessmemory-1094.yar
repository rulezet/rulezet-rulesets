rule TTP_XOR_WriteProcessMemory_1094 {
  strings:
    $key_1094 = { 47 e6 [2] 75 c4 [2] 73 f1 [2] 5d f1 [2] 62 ed }

  condition:
    any of them
}