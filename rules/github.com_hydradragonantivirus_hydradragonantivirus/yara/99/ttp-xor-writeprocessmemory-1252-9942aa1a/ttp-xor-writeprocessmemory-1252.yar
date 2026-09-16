rule TTP_XOR_WriteProcessMemory_1252 {
  strings:
    $key_1252 = { 45 20 [2] 77 02 [2] 71 37 [2] 5f 37 [2] 60 2b }

  condition:
    any of them
}