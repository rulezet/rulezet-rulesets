rule TTP_XOR_WriteProcessMemory_4041 {
  strings:
    $key_4041 = { 17 33 [2] 25 11 [2] 23 24 [2] 0d 24 [2] 32 38 }

  condition:
    any of them
}