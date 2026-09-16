rule TTP_XOR_WriteProcessMemory_7141 {
  strings:
    $key_7141 = { 26 33 [2] 14 11 [2] 12 24 [2] 3c 24 [2] 03 38 }

  condition:
    any of them
}