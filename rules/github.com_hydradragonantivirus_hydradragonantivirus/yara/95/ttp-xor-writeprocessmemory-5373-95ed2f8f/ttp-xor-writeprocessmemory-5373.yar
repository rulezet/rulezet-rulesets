rule TTP_XOR_WriteProcessMemory_5373 {
  strings:
    $key_5373 = { 04 01 [2] 36 23 [2] 30 16 [2] 1e 16 [2] 21 0a }

  condition:
    any of them
}