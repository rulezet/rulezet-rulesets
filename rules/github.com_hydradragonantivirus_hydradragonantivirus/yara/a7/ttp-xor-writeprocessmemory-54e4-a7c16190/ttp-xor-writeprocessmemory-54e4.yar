rule TTP_XOR_WriteProcessMemory_54e4 {
  strings:
    $key_54e4 = { 03 96 [2] 31 b4 [2] 37 81 [2] 19 81 [2] 26 9d }

  condition:
    any of them
}