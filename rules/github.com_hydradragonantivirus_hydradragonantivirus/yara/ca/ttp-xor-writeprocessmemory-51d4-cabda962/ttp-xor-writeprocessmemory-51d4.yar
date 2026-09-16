rule TTP_XOR_WriteProcessMemory_51d4 {
  strings:
    $key_51d4 = { 06 a6 [2] 34 84 [2] 32 b1 [2] 1c b1 [2] 23 ad }

  condition:
    any of them
}