rule TTP_XOR_WriteProcessMemory_1620 {
  strings:
    $key_1620 = { 41 52 [2] 73 70 [2] 75 45 [2] 5b 45 [2] 64 59 }

  condition:
    any of them
}