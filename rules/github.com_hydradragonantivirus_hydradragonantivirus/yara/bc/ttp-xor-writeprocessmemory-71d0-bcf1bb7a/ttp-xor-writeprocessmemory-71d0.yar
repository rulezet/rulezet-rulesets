rule TTP_XOR_WriteProcessMemory_71d0 {
  strings:
    $key_71d0 = { 26 a2 [2] 14 80 [2] 12 b5 [2] 3c b5 [2] 03 a9 }

  condition:
    any of them
}