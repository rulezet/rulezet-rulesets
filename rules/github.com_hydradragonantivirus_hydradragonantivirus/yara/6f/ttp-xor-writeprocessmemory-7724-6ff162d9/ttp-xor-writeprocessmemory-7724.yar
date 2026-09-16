rule TTP_XOR_WriteProcessMemory_7724 {
  strings:
    $key_7724 = { 20 56 [2] 12 74 [2] 14 41 [2] 3a 41 [2] 05 5d }

  condition:
    any of them
}