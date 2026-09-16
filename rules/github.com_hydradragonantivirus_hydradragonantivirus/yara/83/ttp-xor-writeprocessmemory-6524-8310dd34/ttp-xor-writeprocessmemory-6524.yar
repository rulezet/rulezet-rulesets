rule TTP_XOR_WriteProcessMemory_6524 {
  strings:
    $key_6524 = { 32 56 [2] 00 74 [2] 06 41 [2] 28 41 [2] 17 5d }

  condition:
    any of them
}