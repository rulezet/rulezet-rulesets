rule TTP_XOR_WriteProcessMemory_3320 {
  strings:
    $key_3320 = { 64 52 [2] 56 70 [2] 50 45 [2] 7e 45 [2] 41 59 }

  condition:
    any of them
}