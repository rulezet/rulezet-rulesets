rule TTP_XOR_WriteProcessMemory_1d71 {
  strings:
    $key_1d71 = { 4a 03 [2] 78 21 [2] 7e 14 [2] 50 14 [2] 6f 08 }

  condition:
    any of them
}