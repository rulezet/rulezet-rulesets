rule TTP_XOR_WriteProcessMemory_1d40 {
  strings:
    $key_1d40 = { 4a 32 [2] 78 10 [2] 7e 25 [2] 50 25 [2] 6f 39 }

  condition:
    any of them
}