rule TTP_XOR_WriteProcessMemory_4261 {
  strings:
    $key_4261 = { 15 13 [2] 27 31 [2] 21 04 [2] 0f 04 [2] 30 18 }

  condition:
    any of them
}