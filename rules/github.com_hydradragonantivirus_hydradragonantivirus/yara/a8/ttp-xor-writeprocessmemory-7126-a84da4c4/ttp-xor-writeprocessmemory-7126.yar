rule TTP_XOR_WriteProcessMemory_7126 {
  strings:
    $key_7126 = { 26 54 [2] 14 76 [2] 12 43 [2] 3c 43 [2] 03 5f }

  condition:
    any of them
}