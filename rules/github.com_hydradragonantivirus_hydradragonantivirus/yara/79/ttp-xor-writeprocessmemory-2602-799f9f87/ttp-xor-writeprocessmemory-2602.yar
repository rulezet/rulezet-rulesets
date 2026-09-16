rule TTP_XOR_WriteProcessMemory_2602 {
  strings:
    $key_2602 = { 71 70 [2] 43 52 [2] 45 67 [2] 6b 67 [2] 54 7b }

  condition:
    any of them
}