rule TTP_XOR_WriteProcessMemory_1ce2 {
  strings:
    $key_1ce2 = { 4b 90 [2] 79 b2 [2] 7f 87 [2] 51 87 [2] 6e 9b }

  condition:
    any of them
}