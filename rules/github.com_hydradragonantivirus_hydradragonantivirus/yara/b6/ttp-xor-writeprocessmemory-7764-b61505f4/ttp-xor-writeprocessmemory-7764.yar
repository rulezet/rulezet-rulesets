rule TTP_XOR_WriteProcessMemory_7764 {
  strings:
    $key_7764 = { 20 16 [2] 12 34 [2] 14 01 [2] 3a 01 [2] 05 1d }

  condition:
    any of them
}