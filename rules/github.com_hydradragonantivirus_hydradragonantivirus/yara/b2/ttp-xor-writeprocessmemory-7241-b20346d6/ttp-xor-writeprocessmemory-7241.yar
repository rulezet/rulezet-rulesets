rule TTP_XOR_WriteProcessMemory_7241 {
  strings:
    $key_7241 = { 25 33 [2] 17 11 [2] 11 24 [2] 3f 24 [2] 00 38 }

  condition:
    any of them
}