rule TTP_XOR_WriteProcessMemory_1206 {
  strings:
    $key_1206 = { 45 74 [2] 77 56 [2] 71 63 [2] 5f 63 [2] 60 7f }

  condition:
    any of them
}