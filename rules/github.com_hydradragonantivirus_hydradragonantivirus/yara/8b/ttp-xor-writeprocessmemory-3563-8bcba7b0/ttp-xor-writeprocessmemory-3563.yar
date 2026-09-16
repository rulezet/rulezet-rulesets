rule TTP_XOR_WriteProcessMemory_3563 {
  strings:
    $key_3563 = { 62 11 [2] 50 33 [2] 56 06 [2] 78 06 [2] 47 1a }

  condition:
    any of them
}