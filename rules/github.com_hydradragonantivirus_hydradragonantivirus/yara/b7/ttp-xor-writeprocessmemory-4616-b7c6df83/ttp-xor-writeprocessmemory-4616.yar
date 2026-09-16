rule TTP_XOR_WriteProcessMemory_4616 {
  strings:
    $key_4616 = { 11 64 [2] 23 46 [2] 25 73 [2] 0b 73 [2] 34 6f }

  condition:
    any of them
}