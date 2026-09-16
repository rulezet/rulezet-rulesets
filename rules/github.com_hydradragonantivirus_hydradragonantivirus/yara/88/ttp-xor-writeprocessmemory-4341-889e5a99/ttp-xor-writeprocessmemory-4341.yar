rule TTP_XOR_WriteProcessMemory_4341 {
  strings:
    $key_4341 = { 14 33 [2] 26 11 [2] 20 24 [2] 0e 24 [2] 31 38 }

  condition:
    any of them
}