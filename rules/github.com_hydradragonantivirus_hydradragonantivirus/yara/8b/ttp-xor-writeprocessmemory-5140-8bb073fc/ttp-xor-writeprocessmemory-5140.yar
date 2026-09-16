rule TTP_XOR_WriteProcessMemory_5140 {
  strings:
    $key_5140 = { 06 32 [2] 34 10 [2] 32 25 [2] 1c 25 [2] 23 39 }

  condition:
    any of them
}