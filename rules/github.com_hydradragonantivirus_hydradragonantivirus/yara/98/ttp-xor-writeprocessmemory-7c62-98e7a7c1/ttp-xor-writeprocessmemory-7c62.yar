rule TTP_XOR_WriteProcessMemory_7c62 {
  strings:
    $key_7c62 = { 2b 10 [2] 19 32 [2] 1f 07 [2] 31 07 [2] 0e 1b }

  condition:
    any of them
}