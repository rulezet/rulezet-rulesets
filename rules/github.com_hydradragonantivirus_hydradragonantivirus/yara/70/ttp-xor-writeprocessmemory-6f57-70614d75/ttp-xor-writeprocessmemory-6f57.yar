rule TTP_XOR_WriteProcessMemory_6f57 {
  strings:
    $key_6f57 = { 38 25 [2] 0a 07 [2] 0c 32 [2] 22 32 [2] 1d 2e }

  condition:
    any of them
}