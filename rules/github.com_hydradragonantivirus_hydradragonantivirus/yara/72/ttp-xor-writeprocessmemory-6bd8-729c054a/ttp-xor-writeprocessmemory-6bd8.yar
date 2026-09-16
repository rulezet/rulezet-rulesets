rule TTP_XOR_WriteProcessMemory_6bd8 {
  strings:
    $key_6bd8 = { 3c aa [2] 0e 88 [2] 08 bd [2] 26 bd [2] 19 a1 }

  condition:
    any of them
}