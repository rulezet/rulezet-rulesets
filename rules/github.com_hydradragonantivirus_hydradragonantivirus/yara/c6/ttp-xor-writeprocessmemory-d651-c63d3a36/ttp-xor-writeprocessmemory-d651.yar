rule TTP_XOR_WriteProcessMemory_d651 {
  strings:
    $key_d651 = { 81 23 [2] b3 01 [2] b5 34 [2] 9b 34 [2] a4 28 }

  condition:
    any of them
}