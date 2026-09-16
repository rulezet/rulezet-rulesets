rule TTP_XOR_WriteProcessMemory_1820 {
  strings:
    $key_1820 = { 4f 52 [2] 7d 70 [2] 7b 45 [2] 55 45 [2] 6a 59 }

  condition:
    any of them
}