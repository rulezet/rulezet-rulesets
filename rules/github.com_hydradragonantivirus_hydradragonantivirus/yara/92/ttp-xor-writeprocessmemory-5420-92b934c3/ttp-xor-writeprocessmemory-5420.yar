rule TTP_XOR_WriteProcessMemory_5420 {
  strings:
    $key_5420 = { 03 52 [2] 31 70 [2] 37 45 [2] 19 45 [2] 26 59 }

  condition:
    any of them
}