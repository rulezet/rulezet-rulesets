rule TTP_XOR_WriteProcessMemory_7ba9 {
  strings:
    $key_7ba9 = { 2c db [2] 1e f9 [2] 18 cc [2] 36 cc [2] 09 d0 }

  condition:
    any of them
}