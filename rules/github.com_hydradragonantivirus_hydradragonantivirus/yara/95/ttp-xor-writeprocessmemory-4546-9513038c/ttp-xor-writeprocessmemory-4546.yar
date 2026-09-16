rule TTP_XOR_WriteProcessMemory_4546 {
  strings:
    $key_4546 = { 12 34 [2] 20 16 [2] 26 23 [2] 08 23 [2] 37 3f }

  condition:
    any of them
}