rule TTP_XOR_WriteProcessMemory_3433 {
  strings:
    $key_3433 = { 63 41 [2] 51 63 [2] 57 56 [2] 79 56 [2] 46 4a }

  condition:
    any of them
}