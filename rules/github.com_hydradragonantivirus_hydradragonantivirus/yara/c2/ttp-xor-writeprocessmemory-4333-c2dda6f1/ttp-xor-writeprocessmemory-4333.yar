rule TTP_XOR_WriteProcessMemory_4333 {
  strings:
    $key_4333 = { 14 41 [2] 26 63 [2] 20 56 [2] 0e 56 [2] 31 4a }

  condition:
    any of them
}