rule TTP_XOR_WriteProcessMemory_51d5 {
  strings:
    $key_51d5 = { 06 a7 [2] 34 85 [2] 32 b0 [2] 1c b0 [2] 23 ac }

  condition:
    any of them
}