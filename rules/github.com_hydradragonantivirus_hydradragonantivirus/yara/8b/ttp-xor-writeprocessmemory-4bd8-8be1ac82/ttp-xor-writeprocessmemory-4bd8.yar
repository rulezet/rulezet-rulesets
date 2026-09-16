rule TTP_XOR_WriteProcessMemory_4bd8 {
  strings:
    $key_4bd8 = { 1c aa [2] 2e 88 [2] 28 bd [2] 06 bd [2] 39 a1 }

  condition:
    any of them
}