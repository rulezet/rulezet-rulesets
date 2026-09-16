rule TTP_XOR_WriteProcessMemory_4620 {
  strings:
    $key_4620 = { 11 52 [2] 23 70 [2] 25 45 [2] 0b 45 [2] 34 59 }

  condition:
    any of them
}