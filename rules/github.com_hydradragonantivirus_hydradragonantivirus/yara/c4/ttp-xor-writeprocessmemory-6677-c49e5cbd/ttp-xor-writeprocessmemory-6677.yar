rule TTP_XOR_WriteProcessMemory_6677 {
  strings:
    $key_6677 = { 31 05 [2] 03 27 [2] 05 12 [2] 2b 12 [2] 14 0e }

  condition:
    any of them
}