rule TTP_XOR_WriteProcessMemory_3740 {
  strings:
    $key_3740 = { 60 32 [2] 52 10 [2] 54 25 [2] 7a 25 [2] 45 39 }

  condition:
    any of them
}