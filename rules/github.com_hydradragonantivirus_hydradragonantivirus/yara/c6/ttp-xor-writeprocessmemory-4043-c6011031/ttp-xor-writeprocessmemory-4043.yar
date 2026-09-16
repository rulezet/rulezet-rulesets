rule TTP_XOR_WriteProcessMemory_4043 {
  strings:
    $key_4043 = { 17 31 [2] 25 13 [2] 23 26 [2] 0d 26 [2] 32 3a }

  condition:
    any of them
}