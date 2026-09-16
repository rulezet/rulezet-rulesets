rule TTP_XOR_WriteProcessMemory_5747 {
  strings:
    $key_5747 = { 00 35 [2] 32 17 [2] 34 22 [2] 1a 22 [2] 25 3e }

  condition:
    any of them
}