rule TTP_XOR_WriteProcessMemory_79f2 {
  strings:
    $key_79f2 = { 2e 80 [2] 1c a2 [2] 1a 97 [2] 34 97 [2] 0b 8b }

  condition:
    any of them
}