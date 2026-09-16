rule TTP_XOR_WriteProcessMemory_7853 {
  strings:
    $key_7853 = { 2f 21 [2] 1d 03 [2] 1b 36 [2] 35 36 [2] 0a 2a }

  condition:
    any of them
}