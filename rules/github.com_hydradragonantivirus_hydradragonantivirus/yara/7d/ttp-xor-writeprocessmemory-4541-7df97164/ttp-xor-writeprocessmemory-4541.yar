rule TTP_XOR_WriteProcessMemory_4541 {
  strings:
    $key_4541 = { 12 33 [2] 20 11 [2] 26 24 [2] 08 24 [2] 37 38 }

  condition:
    any of them
}