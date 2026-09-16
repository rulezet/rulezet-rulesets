rule TTP_XOR_WriteProcessMemory_71d1 {
  strings:
    $key_71d1 = { 26 a3 [2] 14 81 [2] 12 b4 [2] 3c b4 [2] 03 a8 }

  condition:
    any of them
}