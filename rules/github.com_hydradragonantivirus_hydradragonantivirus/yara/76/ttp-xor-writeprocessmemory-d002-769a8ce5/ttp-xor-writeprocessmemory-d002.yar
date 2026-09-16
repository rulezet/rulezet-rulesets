rule TTP_XOR_WriteProcessMemory_d002 {
  strings:
    $key_d002 = { 87 70 [2] b5 52 [2] b3 67 [2] 9d 67 [2] a2 7b }

  condition:
    any of them
}