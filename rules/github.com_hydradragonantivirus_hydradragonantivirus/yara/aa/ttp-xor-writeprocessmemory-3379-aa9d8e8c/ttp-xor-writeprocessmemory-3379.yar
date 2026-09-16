rule TTP_XOR_WriteProcessMemory_3379 {
  strings:
    $key_3379 = { 64 0b [2] 56 29 [2] 50 1c [2] 7e 1c [2] 41 00 }

  condition:
    any of them
}