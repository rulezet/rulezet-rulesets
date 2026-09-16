rule TTP_XOR_WriteProcessMemory_5361 {
  strings:
    $key_5361 = { 04 13 [2] 36 31 [2] 30 04 [2] 1e 04 [2] 21 18 }

  condition:
    any of them
}