rule TTP_XOR_WriteProcessMemory_5dc8 {
  strings:
    $key_5dc8 = { 0a ba [2] 38 98 [2] 3e ad [2] 10 ad [2] 2f b1 }

  condition:
    any of them
}