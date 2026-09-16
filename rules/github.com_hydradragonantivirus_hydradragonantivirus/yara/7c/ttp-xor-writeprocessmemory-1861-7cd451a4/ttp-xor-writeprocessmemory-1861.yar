rule TTP_XOR_WriteProcessMemory_1861 {
  strings:
    $key_1861 = { 4f 13 [2] 7d 31 [2] 7b 04 [2] 55 04 [2] 6a 18 }

  condition:
    any of them
}