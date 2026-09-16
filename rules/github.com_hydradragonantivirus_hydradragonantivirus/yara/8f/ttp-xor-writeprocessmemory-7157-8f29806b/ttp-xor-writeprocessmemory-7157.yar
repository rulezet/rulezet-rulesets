rule TTP_XOR_WriteProcessMemory_7157 {
  strings:
    $key_7157 = { 26 25 [2] 14 07 [2] 12 32 [2] 3c 32 [2] 03 2e }

  condition:
    any of them
}