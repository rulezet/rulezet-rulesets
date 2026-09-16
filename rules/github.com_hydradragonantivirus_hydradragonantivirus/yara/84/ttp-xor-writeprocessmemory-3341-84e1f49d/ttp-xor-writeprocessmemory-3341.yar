rule TTP_XOR_WriteProcessMemory_3341 {
  strings:
    $key_3341 = { 64 33 [2] 56 11 [2] 50 24 [2] 7e 24 [2] 41 38 }

  condition:
    any of them
}