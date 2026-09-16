rule TTP_XOR_WriteProcessMemory_1072 {
  strings:
    $key_1072 = { 47 00 [2] 75 22 [2] 73 17 [2] 5d 17 [2] 62 0b }

  condition:
    any of them
}