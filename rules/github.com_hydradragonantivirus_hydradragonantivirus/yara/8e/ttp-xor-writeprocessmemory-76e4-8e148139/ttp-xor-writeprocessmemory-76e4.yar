rule TTP_XOR_WriteProcessMemory_76e4 {
  strings:
    $key_76e4 = { 21 96 [2] 13 b4 [2] 15 81 [2] 3b 81 [2] 04 9d }

  condition:
    any of them
}