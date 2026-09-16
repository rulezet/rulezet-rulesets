rule TTP_XOR_WriteProcessMemory_1966 {
  strings:
    $key_1966 = { 4e 14 [2] 7c 36 [2] 7a 03 [2] 54 03 [2] 6b 1f }

  condition:
    any of them
}