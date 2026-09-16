rule TTP_XOR_WriteProcessMemory_72f7 {
  strings:
    $key_72f7 = { 25 85 [2] 17 a7 [2] 11 92 [2] 3f 92 [2] 00 8e }

  condition:
    any of them
}