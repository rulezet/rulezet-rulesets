rule TTP_XOR_WriteProcessMemory_4346 {
  strings:
    $key_4346 = { 14 34 [2] 26 16 [2] 20 23 [2] 0e 23 [2] 31 3f }

  condition:
    any of them
}