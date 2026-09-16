rule TTP_XOR_WriteProcessMemory_3656 {
  strings:
    $key_3656 = { 61 24 [2] 53 06 [2] 55 33 [2] 7b 33 [2] 44 2f }

  condition:
    any of them
}