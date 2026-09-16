rule TTP_XOR_WriteProcessMemory_1616 {
  strings:
    $key_1616 = { 41 64 [2] 73 46 [2] 75 73 [2] 5b 73 [2] 64 6f }

  condition:
    any of them
}