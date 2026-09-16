rule TTP_XOR_WriteProcessMemory_3860 {
  strings:
    $key_3860 = { 6f 12 [2] 5d 30 [2] 5b 05 [2] 75 05 [2] 4a 19 }

  condition:
    any of them
}