rule TTP_XOR_WriteProcessMemory_45e4 {
  strings:
    $key_45e4 = { 12 96 [2] 20 b4 [2] 26 81 [2] 08 81 [2] 37 9d }

  condition:
    any of them
}