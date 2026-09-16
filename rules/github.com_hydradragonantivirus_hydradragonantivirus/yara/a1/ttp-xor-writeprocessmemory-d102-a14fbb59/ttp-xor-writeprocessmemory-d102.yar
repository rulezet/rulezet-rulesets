rule TTP_XOR_WriteProcessMemory_d102 {
  strings:
    $key_d102 = { 86 70 [2] b4 52 [2] b2 67 [2] 9c 67 [2] a3 7b }

  condition:
    any of them
}