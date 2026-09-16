rule TTP_XOR_WriteProcessMemory_d052 {
  strings:
    $key_d052 = { 87 20 [2] b5 02 [2] b3 37 [2] 9d 37 [2] a2 2b }

  condition:
    any of them
}