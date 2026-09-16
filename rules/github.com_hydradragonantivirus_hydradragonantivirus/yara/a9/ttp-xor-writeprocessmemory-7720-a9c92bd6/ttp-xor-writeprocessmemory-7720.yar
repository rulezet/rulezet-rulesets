rule TTP_XOR_WriteProcessMemory_7720 {
  strings:
    $key_7720 = { 20 52 [2] 12 70 [2] 14 45 [2] 3a 45 [2] 05 59 }

  condition:
    any of them
}