rule TTP_XOR_WriteProcessMemory_d632 {
  strings:
    $key_d632 = { 81 40 [2] b3 62 [2] b5 57 [2] 9b 57 [2] a4 4b }

  condition:
    any of them
}