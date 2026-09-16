rule TTP_XOR_WriteProcessMemory_1085 {
  strings:
    $key_1085 = { 47 f7 [2] 75 d5 [2] 73 e0 [2] 5d e0 [2] 62 fc }

  condition:
    any of them
}