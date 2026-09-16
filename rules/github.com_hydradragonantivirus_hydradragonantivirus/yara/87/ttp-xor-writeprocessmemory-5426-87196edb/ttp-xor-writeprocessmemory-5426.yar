rule TTP_XOR_WriteProcessMemory_5426 {
  strings:
    $key_5426 = { 03 54 [2] 31 76 [2] 37 43 [2] 19 43 [2] 26 5f }

  condition:
    any of them
}