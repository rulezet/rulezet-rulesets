rule TTP_XOR_WriteProcessMemory_1e62 {
  strings:
    $key_1e62 = { 49 10 [2] 7b 32 [2] 7d 07 [2] 53 07 [2] 6c 1b }

  condition:
    any of them
}