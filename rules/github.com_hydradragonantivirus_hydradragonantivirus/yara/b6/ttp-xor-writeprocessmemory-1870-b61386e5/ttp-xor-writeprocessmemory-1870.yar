rule TTP_XOR_WriteProcessMemory_1870 {
  strings:
    $key_1870 = { 4f 02 [2] 7d 20 [2] 7b 15 [2] 55 15 [2] 6a 09 }

  condition:
    any of them
}