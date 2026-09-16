rule TTP_XOR_WriteProcessMemory_5446 {
  strings:
    $key_5446 = { 03 34 [2] 31 16 [2] 37 23 [2] 19 23 [2] 26 3f }

  condition:
    any of them
}