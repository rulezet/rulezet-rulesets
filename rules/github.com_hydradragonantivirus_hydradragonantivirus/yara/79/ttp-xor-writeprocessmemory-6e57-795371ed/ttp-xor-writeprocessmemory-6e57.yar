rule TTP_XOR_WriteProcessMemory_6e57 {
  strings:
    $key_6e57 = { 39 25 [2] 0b 07 [2] 0d 32 [2] 23 32 [2] 1c 2e }

  condition:
    any of them
}