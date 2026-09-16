rule TTP_XOR_WriteProcessMemory_46e4 {
  strings:
    $key_46e4 = { 11 96 [2] 23 b4 [2] 25 81 [2] 0b 81 [2] 34 9d }

  condition:
    any of them
}