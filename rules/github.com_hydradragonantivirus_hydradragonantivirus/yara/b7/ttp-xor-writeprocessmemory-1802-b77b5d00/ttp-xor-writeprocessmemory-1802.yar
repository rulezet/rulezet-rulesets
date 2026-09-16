rule TTP_XOR_WriteProcessMemory_1802 {
  strings:
    $key_1802 = { 4f 70 [2] 7d 52 [2] 7b 67 [2] 55 67 [2] 6a 7b }

  condition:
    any of them
}