rule TTP_XOR_WriteProcessMemory_5362 {
  strings:
    $key_5362 = { 04 10 [2] 36 32 [2] 30 07 [2] 1e 07 [2] 21 1b }

  condition:
    any of them
}