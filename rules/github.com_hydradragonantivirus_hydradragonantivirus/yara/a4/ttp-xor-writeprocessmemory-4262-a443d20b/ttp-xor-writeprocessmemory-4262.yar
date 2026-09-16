rule TTP_XOR_WriteProcessMemory_4262 {
  strings:
    $key_4262 = { 15 10 [2] 27 32 [2] 21 07 [2] 0f 07 [2] 30 1b }

  condition:
    any of them
}