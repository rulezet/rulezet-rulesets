rule TTP_XOR_WriteProcessMemory_5241 {
  strings:
    $key_5241 = { 05 33 [2] 37 11 [2] 31 24 [2] 1f 24 [2] 20 38 }

  condition:
    any of them
}