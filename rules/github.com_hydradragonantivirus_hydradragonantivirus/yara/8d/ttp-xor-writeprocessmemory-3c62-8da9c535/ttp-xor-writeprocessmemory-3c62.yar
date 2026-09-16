rule TTP_XOR_WriteProcessMemory_3c62 {
  strings:
    $key_3c62 = { 6b 10 [2] 59 32 [2] 5f 07 [2] 71 07 [2] 4e 1b }

  condition:
    any of them
}