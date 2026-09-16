rule TTP_XOR_WriteProcessMemory_1956 {
  strings:
    $key_1956 = { 4e 24 [2] 7c 06 [2] 7a 33 [2] 54 33 [2] 6b 2f }

  condition:
    any of them
}