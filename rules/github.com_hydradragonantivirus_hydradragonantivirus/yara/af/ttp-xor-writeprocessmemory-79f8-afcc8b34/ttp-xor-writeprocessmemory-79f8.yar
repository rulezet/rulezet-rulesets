rule TTP_XOR_WriteProcessMemory_79f8 {
  strings:
    $key_79f8 = { 2e 8a [2] 1c a8 [2] 1a 9d [2] 34 9d [2] 0b 81 }

  condition:
    any of them
}