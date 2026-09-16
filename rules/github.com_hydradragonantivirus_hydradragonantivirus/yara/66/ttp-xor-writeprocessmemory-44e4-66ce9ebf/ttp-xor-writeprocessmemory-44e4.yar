rule TTP_XOR_WriteProcessMemory_44e4 {
  strings:
    $key_44e4 = { 13 96 [2] 21 b4 [2] 27 81 [2] 09 81 [2] 36 9d }

  condition:
    any of them
}