rule TTP_XOR_WriteProcessMemory_3571 {
  strings:
    $key_3571 = { 62 03 [2] 50 21 [2] 56 14 [2] 78 14 [2] 47 08 }

  condition:
    any of them
}