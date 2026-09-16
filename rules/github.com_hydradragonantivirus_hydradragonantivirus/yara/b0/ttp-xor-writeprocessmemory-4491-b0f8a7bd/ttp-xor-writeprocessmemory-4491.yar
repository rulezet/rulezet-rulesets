rule TTP_XOR_WriteProcessMemory_4491 {
  strings:
    $key_4491 = { 13 e3 [2] 21 c1 [2] 27 f4 [2] 09 f4 [2] 36 e8 }

  condition:
    any of them
}