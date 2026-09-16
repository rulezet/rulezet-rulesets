rule TTP_XOR_WriteProcessMemory_7772 {
  strings:
    $key_7772 = { 20 00 [2] 12 22 [2] 14 17 [2] 3a 17 [2] 05 0b }

  condition:
    any of them
}