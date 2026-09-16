rule TTP_XOR_WriteProcessMemory_5041 {
  strings:
    $key_5041 = { 07 33 [2] 35 11 [2] 33 24 [2] 1d 24 [2] 22 38 }

  condition:
    any of them
}