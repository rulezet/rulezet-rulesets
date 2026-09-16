rule TTP_XOR_WriteProcessMemory_3510 {
  strings:
    $key_3510 = { 62 62 [2] 50 40 [2] 56 75 [2] 78 75 [2] 47 69 }

  condition:
    any of them
}