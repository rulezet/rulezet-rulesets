rule TTP_XOR_WriteProcessMemory_4756 {
  strings:
    $key_4756 = { 10 24 [2] 22 06 [2] 24 33 [2] 0a 33 [2] 35 2f }

  condition:
    any of them
}