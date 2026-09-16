rule TTP_XOR_WriteProcessMemory_7467 {
  strings:
    $key_7467 = { 23 15 [2] 11 37 [2] 17 02 [2] 39 02 [2] 06 1e }

  condition:
    any of them
}