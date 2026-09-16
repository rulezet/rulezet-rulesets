rule TTP_XOR_WriteProcessMemory_5fd1 {
  strings:
    $key_5fd1 = { 08 a3 [2] 3a 81 [2] 3c b4 [2] 12 b4 [2] 2d a8 }

  condition:
    any of them
}