rule TTP_XOR_WriteProcessMemory_3316 {
  strings:
    $key_3316 = { 64 64 [2] 56 46 [2] 50 73 [2] 7e 73 [2] 41 6f }

  condition:
    any of them
}