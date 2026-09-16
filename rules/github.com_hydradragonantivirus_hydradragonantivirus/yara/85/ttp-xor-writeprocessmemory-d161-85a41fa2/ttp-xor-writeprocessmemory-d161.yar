rule TTP_XOR_WriteProcessMemory_d161 {
  strings:
    $key_d161 = { 86 13 [2] b4 31 [2] b2 04 [2] 9c 04 [2] a3 18 }

  condition:
    any of them
}