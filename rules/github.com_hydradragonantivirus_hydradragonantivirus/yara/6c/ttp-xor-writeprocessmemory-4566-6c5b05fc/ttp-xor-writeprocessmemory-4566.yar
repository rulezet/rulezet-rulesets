rule TTP_XOR_WriteProcessMemory_4566 {
  strings:
    $key_4566 = { 12 14 [2] 20 36 [2] 26 03 [2] 08 03 [2] 37 1f }

  condition:
    any of them
}