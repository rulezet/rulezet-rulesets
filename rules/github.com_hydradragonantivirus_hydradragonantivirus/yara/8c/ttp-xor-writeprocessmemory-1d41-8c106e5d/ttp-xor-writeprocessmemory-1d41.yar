rule TTP_XOR_WriteProcessMemory_1d41 {
  strings:
    $key_1d41 = { 4a 33 [2] 78 11 [2] 7e 24 [2] 50 24 [2] 6f 38 }

  condition:
    any of them
}