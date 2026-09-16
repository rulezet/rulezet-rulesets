rule TTP_XOR_WriteProcessMemory_2a22 {
  strings:
    $key_2a22 = { 7d 50 [2] 4f 72 [2] 49 47 [2] 67 47 [2] 58 5b }

  condition:
    any of them
}