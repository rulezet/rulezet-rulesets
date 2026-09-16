rule TTP_XOR_WriteProcessMemory_7220 {
  strings:
    $key_7220 = { 25 52 [2] 17 70 [2] 11 45 [2] 3f 45 [2] 00 59 }

  condition:
    any of them
}