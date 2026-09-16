rule TTP_XOR_WriteProcessMemory_1041 {
  strings:
    $key_1041 = { 47 33 [2] 75 11 [2] 73 24 [2] 5d 24 [2] 62 38 }

  condition:
    any of them
}