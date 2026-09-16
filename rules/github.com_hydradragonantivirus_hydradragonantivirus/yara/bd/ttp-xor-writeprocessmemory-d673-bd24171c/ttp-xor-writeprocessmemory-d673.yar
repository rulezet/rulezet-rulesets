rule TTP_XOR_WriteProcessMemory_d673 {
  strings:
    $key_d673 = { 81 01 [2] b3 23 [2] b5 16 [2] 9b 16 [2] a4 0a }

  condition:
    any of them
}