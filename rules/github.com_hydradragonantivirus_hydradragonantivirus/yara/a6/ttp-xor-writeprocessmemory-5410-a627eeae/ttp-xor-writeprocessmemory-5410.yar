rule TTP_XOR_WriteProcessMemory_5410 {
  strings:
    $key_5410 = { 03 62 [2] 31 40 [2] 37 75 [2] 19 75 [2] 26 69 }

  condition:
    any of them
}