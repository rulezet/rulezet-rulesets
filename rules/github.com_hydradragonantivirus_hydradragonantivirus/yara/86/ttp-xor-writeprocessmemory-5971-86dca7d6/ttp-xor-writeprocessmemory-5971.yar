rule TTP_XOR_WriteProcessMemory_5971 {
  strings:
    $key_5971 = { 0e 03 [2] 3c 21 [2] 3a 14 [2] 14 14 [2] 2b 08 }

  condition:
    any of them
}