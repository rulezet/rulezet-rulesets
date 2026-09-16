rule TTP_XOR_WriteProcessMemory_4720 {
  strings:
    $key_4720 = { 10 52 [2] 22 70 [2] 24 45 [2] 0a 45 [2] 35 59 }

  condition:
    any of them
}