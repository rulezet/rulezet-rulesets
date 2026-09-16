rule TTP_XOR_WriteProcessMemory_07c3 {
  strings:
    $key_07c3 = { 50 b1 [2] 62 93 [2] 64 a6 [2] 4a a6 [2] 75 ba }

  condition:
    any of them
}