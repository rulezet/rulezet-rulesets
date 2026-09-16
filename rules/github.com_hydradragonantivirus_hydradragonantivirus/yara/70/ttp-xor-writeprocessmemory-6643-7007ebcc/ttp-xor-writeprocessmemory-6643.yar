rule TTP_XOR_WriteProcessMemory_6643 {
  strings:
    $key_6643 = { 31 31 [2] 03 13 [2] 05 26 [2] 2b 26 [2] 14 3a }

  condition:
    any of them
}