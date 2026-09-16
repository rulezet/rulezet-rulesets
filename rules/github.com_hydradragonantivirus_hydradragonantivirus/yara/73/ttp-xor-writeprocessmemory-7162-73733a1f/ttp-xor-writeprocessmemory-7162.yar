rule TTP_XOR_WriteProcessMemory_7162 {
  strings:
    $key_7162 = { 26 10 [2] 14 32 [2] 12 07 [2] 3c 07 [2] 03 1b }

  condition:
    any of them
}