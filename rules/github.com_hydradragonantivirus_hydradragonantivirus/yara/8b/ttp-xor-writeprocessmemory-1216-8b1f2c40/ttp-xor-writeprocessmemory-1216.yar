rule TTP_XOR_WriteProcessMemory_1216 {
  strings:
    $key_1216 = { 45 64 [2] 77 46 [2] 71 73 [2] 5f 73 [2] 60 6f }

  condition:
    any of them
}