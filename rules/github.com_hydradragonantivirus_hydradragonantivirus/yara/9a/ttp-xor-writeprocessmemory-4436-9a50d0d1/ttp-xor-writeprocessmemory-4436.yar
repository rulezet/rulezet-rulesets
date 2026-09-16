rule TTP_XOR_WriteProcessMemory_4436 {
  strings:
    $key_4436 = { 13 44 [2] 21 66 [2] 27 53 [2] 09 53 [2] 36 4f }

  condition:
    any of them
}