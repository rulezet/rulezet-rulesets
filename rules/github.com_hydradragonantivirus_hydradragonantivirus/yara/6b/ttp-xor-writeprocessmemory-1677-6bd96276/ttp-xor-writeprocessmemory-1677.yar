rule TTP_XOR_WriteProcessMemory_1677 {
  strings:
    $key_1677 = { 41 05 [2] 73 27 [2] 75 12 [2] 5b 12 [2] 64 0e }

  condition:
    any of them
}