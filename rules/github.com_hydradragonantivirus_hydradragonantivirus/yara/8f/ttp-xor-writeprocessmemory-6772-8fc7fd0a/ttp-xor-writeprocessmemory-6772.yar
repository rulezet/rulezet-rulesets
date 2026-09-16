rule TTP_XOR_WriteProcessMemory_6772 {
  strings:
    $key_6772 = { 30 00 [2] 02 22 [2] 04 17 [2] 2a 17 [2] 15 0b }

  condition:
    any of them
}