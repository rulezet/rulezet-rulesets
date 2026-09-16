rule TTP_XOR_WriteProcessMemory_4240 {
  strings:
    $key_4240 = { 15 32 [2] 27 10 [2] 21 25 [2] 0f 25 [2] 30 39 }

  condition:
    any of them
}