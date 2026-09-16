rule TTP_XOR_WriteProcessMemory_d674 {
  strings:
    $key_d674 = { 81 06 [2] b3 24 [2] b5 11 [2] 9b 11 [2] a4 0d }

  condition:
    any of them
}