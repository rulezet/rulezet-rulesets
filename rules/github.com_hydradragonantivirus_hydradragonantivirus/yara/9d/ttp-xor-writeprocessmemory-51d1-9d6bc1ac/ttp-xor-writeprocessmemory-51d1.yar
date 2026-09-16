rule TTP_XOR_WriteProcessMemory_51d1 {
  strings:
    $key_51d1 = { 06 a3 [2] 34 81 [2] 32 b4 [2] 1c b4 [2] 23 a8 }

  condition:
    any of them
}