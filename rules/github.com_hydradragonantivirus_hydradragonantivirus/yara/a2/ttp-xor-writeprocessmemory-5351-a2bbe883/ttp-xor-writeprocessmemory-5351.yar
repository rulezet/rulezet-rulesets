rule TTP_XOR_WriteProcessMemory_5351 {
  strings:
    $key_5351 = { 04 23 [2] 36 01 [2] 30 34 [2] 1e 34 [2] 21 28 }

  condition:
    any of them
}