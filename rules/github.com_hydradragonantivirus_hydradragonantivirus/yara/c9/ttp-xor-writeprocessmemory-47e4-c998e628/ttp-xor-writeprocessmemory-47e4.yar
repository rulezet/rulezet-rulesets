rule TTP_XOR_WriteProcessMemory_47e4 {
  strings:
    $key_47e4 = { 10 96 [2] 22 b4 [2] 24 81 [2] 0a 81 [2] 35 9d }

  condition:
    any of them
}