rule TTP_XOR_WriteProcessMemory_07c1 {
  strings:
    $key_07c1 = { 50 b3 [2] 62 91 [2] 64 a4 [2] 4a a4 [2] 75 b8 }

  condition:
    any of them
}