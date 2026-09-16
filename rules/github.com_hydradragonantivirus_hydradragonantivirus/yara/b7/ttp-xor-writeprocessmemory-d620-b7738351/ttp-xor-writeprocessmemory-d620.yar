rule TTP_XOR_WriteProcessMemory_d620 {
  strings:
    $key_d620 = { 81 52 [2] b3 70 [2] b5 45 [2] 9b 45 [2] a4 59 }

  condition:
    any of them
}