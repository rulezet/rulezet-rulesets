rule TTP_XOR_WriteProcessMemory_3533 {
  strings:
    $key_3533 = { 62 41 [2] 50 63 [2] 56 56 [2] 78 56 [2] 47 4a }

  condition:
    any of them
}