rule TTP_XOR_WriteProcessMemory_65e4 {
  strings:
    $key_65e4 = { 32 96 [2] 00 b4 [2] 06 81 [2] 28 81 [2] 17 9d }

  condition:
    any of them
}