rule TTP_XOR_WriteProcessMemory_4241 {
  strings:
    $key_4241 = { 15 33 [2] 27 11 [2] 21 24 [2] 0f 24 [2] 30 38 }

  condition:
    any of them
}