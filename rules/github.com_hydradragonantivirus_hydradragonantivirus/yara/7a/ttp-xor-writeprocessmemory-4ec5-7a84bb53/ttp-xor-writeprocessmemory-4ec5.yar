rule TTP_XOR_WriteProcessMemory_4ec5 {
  strings:
    $key_4ec5 = { 19 b7 [2] 2b 95 [2] 2d a0 [2] 03 a0 [2] 3c bc }

  condition:
    any of them
}