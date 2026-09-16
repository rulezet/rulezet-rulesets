rule TTP_XOR_WriteProcessMemory_3300 {
  strings:
    $key_3300 = { 64 72 [2] 56 50 [2] 50 65 [2] 7e 65 [2] 41 79 }

  condition:
    any of them
}