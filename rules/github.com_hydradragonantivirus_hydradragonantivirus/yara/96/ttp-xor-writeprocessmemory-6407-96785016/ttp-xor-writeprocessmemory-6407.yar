rule TTP_XOR_WriteProcessMemory_6407 {
  strings:
    $key_6407 = { 33 75 [2] 01 57 [2] 07 62 [2] 29 62 [2] 16 7e }

  condition:
    any of them
}