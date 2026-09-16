rule TTP_XOR_WriteProcessMemory_4726 {
  strings:
    $key_4726 = { 10 54 [2] 22 76 [2] 24 43 [2] 0a 43 [2] 35 5f }

  condition:
    any of them
}