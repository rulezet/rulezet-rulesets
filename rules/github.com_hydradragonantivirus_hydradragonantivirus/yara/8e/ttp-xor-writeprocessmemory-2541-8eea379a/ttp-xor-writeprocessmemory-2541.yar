rule TTP_XOR_WriteProcessMemory_2541 {
  strings:
    $key_2541 = { 72 33 [2] 40 11 [2] 46 24 [2] 68 24 [2] 57 38 }

  condition:
    any of them
}