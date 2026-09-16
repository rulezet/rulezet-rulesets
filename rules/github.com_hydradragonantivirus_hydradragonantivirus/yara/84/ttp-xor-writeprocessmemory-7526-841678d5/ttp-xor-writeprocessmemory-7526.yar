rule TTP_XOR_WriteProcessMemory_7526 {
  strings:
    $key_7526 = { 22 54 [2] 10 76 [2] 16 43 [2] 38 43 [2] 07 5f }

  condition:
    any of them
}