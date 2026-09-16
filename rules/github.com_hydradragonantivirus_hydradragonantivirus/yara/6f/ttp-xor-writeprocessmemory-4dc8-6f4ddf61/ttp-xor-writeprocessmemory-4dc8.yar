rule TTP_XOR_WriteProcessMemory_4dc8 {
  strings:
    $key_4dc8 = { 1a ba [2] 28 98 [2] 2e ad [2] 00 ad [2] 3f b1 }

  condition:
    any of them
}