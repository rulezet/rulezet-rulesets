rule TTP_XOR_WriteProcessMemory_4643 {
  strings:
    $key_4643 = { 11 31 [2] 23 13 [2] 25 26 [2] 0b 26 [2] 34 3a }

  condition:
    any of them
}