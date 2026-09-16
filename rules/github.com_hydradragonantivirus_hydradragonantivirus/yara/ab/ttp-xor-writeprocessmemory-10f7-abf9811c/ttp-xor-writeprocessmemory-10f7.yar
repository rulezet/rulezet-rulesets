rule TTP_XOR_WriteProcessMemory_10f7 {
  strings:
    $key_10f7 = { 47 85 [2] 75 a7 [2] 73 92 [2] 5d 92 [2] 62 8e }

  condition:
    any of them
}