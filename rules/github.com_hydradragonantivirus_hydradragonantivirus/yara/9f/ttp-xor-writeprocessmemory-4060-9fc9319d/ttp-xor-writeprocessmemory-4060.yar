rule TTP_XOR_WriteProcessMemory_4060 {
  strings:
    $key_4060 = { 17 12 [2] 25 30 [2] 23 05 [2] 0d 05 [2] 32 19 }

  condition:
    any of them
}