rule TTP_XOR_WriteProcessMemory_71d2 {
  strings:
    $key_71d2 = { 26 a0 [2] 14 82 [2] 12 b7 [2] 3c b7 [2] 03 ab }

  condition:
    any of them
}