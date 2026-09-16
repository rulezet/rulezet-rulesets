rule TTP_XOR_WriteProcessMemory_7630 {
  strings:
    $key_7630 = { 21 42 [2] 13 60 [2] 15 55 [2] 3b 55 [2] 04 49 }

  condition:
    any of them
}