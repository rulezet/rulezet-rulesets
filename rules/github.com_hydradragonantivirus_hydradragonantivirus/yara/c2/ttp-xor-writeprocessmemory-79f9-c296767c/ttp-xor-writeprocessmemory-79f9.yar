rule TTP_XOR_WriteProcessMemory_79f9 {
  strings:
    $key_79f9 = { 2e 8b [2] 1c a9 [2] 1a 9c [2] 34 9c [2] 0b 80 }

  condition:
    any of them
}