rule TTP_XOR_WriteProcessMemory_5fb3 {
  strings:
    $key_5fb3 = { 08 c1 [2] 3a e3 [2] 3c d6 [2] 12 d6 [2] 2d ca }

  condition:
    any of them
}