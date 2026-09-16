rule TTP_XOR_WriteProcessMemory_1871 {
  strings:
    $key_1871 = { 4f 03 [2] 7d 21 [2] 7b 14 [2] 55 14 [2] 6a 08 }

  condition:
    any of them
}