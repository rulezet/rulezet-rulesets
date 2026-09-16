rule TTP_XOR_WriteProcessMemory_2341 {
  strings:
    $key_2341 = { 74 33 [2] 46 11 [2] 40 24 [2] 6e 24 [2] 51 38 }

  condition:
    any of them
}