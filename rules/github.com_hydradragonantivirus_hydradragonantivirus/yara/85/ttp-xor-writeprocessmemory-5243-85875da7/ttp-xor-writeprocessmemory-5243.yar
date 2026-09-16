rule TTP_XOR_WriteProcessMemory_5243 {
  strings:
    $key_5243 = { 05 31 [2] 37 13 [2] 31 26 [2] 1f 26 [2] 20 3a }

  condition:
    any of them
}