rule TTP_XOR_WriteProcessMemory_d130 {
  strings:
    $key_d130 = { 86 42 [2] b4 60 [2] b2 55 [2] 9c 55 [2] a3 49 }

  condition:
    any of them
}