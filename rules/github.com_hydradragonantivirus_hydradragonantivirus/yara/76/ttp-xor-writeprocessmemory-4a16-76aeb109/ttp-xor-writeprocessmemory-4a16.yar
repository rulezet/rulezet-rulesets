rule TTP_XOR_WriteProcessMemory_4a16 {
  strings:
    $key_4a16 = { 1d 64 [2] 2f 46 [2] 29 73 [2] 07 73 [2] 38 6f }

  condition:
    any of them
}