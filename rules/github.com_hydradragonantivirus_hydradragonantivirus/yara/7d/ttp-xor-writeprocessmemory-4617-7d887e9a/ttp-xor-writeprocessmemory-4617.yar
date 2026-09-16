rule TTP_XOR_WriteProcessMemory_4617 {
  strings:
    $key_4617 = { 11 65 [2] 23 47 [2] 25 72 [2] 0b 72 [2] 34 6e }

  condition:
    any of them
}