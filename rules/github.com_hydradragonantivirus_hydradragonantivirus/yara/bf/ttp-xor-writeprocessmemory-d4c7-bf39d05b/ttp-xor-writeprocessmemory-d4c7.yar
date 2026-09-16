rule TTP_XOR_WriteProcessMemory_d4c7 {
  strings:
    $key_d4c7 = { 83 b5 [2] b1 97 [2] b7 a2 [2] 99 a2 [2] a6 be }

  condition:
    any of them
}