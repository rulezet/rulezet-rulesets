rule TTP_XOR_WriteProcessMemory_d120 {
  strings:
    $key_d120 = { 86 52 [2] b4 70 [2] b2 45 [2] 9c 45 [2] a3 59 }

  condition:
    any of them
}