rule TTP_XOR_WriteProcessMemory_1847 {
  strings:
    $key_1847 = { 4f 35 [2] 7d 17 [2] 7b 22 [2] 55 22 [2] 6a 3e }

  condition:
    any of them
}