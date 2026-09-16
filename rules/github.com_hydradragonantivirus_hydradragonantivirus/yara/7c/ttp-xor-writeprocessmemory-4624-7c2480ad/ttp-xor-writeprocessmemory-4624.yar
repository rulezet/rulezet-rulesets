rule TTP_XOR_WriteProcessMemory_4624 {
  strings:
    $key_4624 = { 11 56 [2] 23 74 [2] 25 41 [2] 0b 41 [2] 34 5d }

  condition:
    any of them
}