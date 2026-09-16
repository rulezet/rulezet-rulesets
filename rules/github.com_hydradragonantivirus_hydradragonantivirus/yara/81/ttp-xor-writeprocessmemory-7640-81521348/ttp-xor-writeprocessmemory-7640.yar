rule TTP_XOR_WriteProcessMemory_7640 {
  strings:
    $key_7640 = { 21 32 [2] 13 10 [2] 15 25 [2] 3b 25 [2] 04 39 }

  condition:
    any of them
}