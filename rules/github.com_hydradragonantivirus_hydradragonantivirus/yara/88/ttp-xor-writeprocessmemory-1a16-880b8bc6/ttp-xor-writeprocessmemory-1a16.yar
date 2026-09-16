rule TTP_XOR_WriteProcessMemory_1a16 {
  strings:
    $key_1a16 = { 4d 64 [2] 7f 46 [2] 79 73 [2] 57 73 [2] 68 6f }

  condition:
    any of them
}