rule TTP_XOR_WriteProcessMemory_1bd8 {
  strings:
    $key_1bd8 = { 4c aa [2] 7e 88 [2] 78 bd [2] 56 bd [2] 69 a1 }

  condition:
    any of them
}