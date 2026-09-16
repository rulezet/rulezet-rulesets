rule TTP_XOR_WriteProcessMemory_55e7 {
  strings:
    $key_55e7 = { 02 95 [2] 30 b7 [2] 36 82 [2] 18 82 [2] 27 9e }

  condition:
    any of them
}