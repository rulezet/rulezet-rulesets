rule TTP_XOR_WriteProcessMemory_11f2 {
  strings:
    $key_11f2 = { 46 80 [2] 74 a2 [2] 72 97 [2] 5c 97 [2] 63 8b }

  condition:
    any of them
}