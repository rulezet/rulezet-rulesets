rule TTP_XOR_WriteProcessMemory_3f62 {
  strings:
    $key_3f62 = { 68 10 [2] 5a 32 [2] 5c 07 [2] 72 07 [2] 4d 1b }

  condition:
    any of them
}