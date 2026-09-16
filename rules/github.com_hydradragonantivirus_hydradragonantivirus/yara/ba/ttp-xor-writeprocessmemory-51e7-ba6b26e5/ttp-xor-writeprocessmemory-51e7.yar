rule TTP_XOR_WriteProcessMemory_51e7 {
  strings:
    $key_51e7 = { 06 95 [2] 34 b7 [2] 32 82 [2] 1c 82 [2] 23 9e }

  condition:
    any of them
}