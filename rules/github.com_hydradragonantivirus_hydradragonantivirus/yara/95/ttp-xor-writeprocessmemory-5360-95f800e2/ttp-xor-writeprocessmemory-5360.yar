rule TTP_XOR_WriteProcessMemory_5360 {
  strings:
    $key_5360 = { 04 12 [2] 36 30 [2] 30 05 [2] 1e 05 [2] 21 19 }

  condition:
    any of them
}