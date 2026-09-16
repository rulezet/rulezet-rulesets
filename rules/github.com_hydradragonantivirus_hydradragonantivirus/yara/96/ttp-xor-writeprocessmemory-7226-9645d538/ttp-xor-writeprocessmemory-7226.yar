rule TTP_XOR_WriteProcessMemory_7226 {
  strings:
    $key_7226 = { 25 54 [2] 17 76 [2] 11 43 [2] 3f 43 [2] 00 5f }

  condition:
    any of them
}