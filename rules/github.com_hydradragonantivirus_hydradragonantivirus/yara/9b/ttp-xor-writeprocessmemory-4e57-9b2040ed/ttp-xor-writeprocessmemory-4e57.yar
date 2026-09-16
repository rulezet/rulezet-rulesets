rule TTP_XOR_WriteProcessMemory_4e57 {
  strings:
    $key_4e57 = { 19 25 [2] 2b 07 [2] 2d 32 [2] 03 32 [2] 3c 2e }

  condition:
    any of them
}