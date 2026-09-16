rule TTP_XOR_WriteProcessMemory_4200 {
  strings:
    $key_4200 = { 15 72 [2] 27 50 [2] 21 65 [2] 0f 65 [2] 30 79 }

  condition:
    any of them
}