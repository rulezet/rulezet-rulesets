rule TTP_XOR_WriteProcessMemory_4473 {
  strings:
    $key_4473 = { 13 01 [2] 21 23 [2] 27 16 [2] 09 16 [2] 36 0a }

  condition:
    any of them
}