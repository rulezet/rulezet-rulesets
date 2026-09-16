rule TTP_XOR_WriteProcessMemory_7432 {
  strings:
    $key_7432 = { 23 40 [2] 11 62 [2] 17 57 [2] 39 57 [2] 06 4b }

  condition:
    any of them
}