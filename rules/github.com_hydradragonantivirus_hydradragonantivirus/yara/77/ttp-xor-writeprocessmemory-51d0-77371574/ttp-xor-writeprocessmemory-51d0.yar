rule TTP_XOR_WriteProcessMemory_51d0 {
  strings:
    $key_51d0 = { 06 a2 [2] 34 80 [2] 32 b5 [2] 1c b5 [2] 23 a9 }

  condition:
    any of them
}