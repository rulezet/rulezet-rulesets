rule TTP_XOR_WriteProcessMemory_7120 {
  strings:
    $key_7120 = { 26 52 [2] 14 70 [2] 12 45 [2] 3c 45 [2] 03 59 }

  condition:
    any of them
}