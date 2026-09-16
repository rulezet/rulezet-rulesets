rule TTP_XOR_WriteProcessMemory_1256 {
  strings:
    $key_1256 = { 45 24 [2] 77 06 [2] 71 33 [2] 5f 33 [2] 60 2f }

  condition:
    any of them
}