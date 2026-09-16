rule TTP_XOR_WriteProcessMemory_3dc8 {
  strings:
    $key_3dc8 = { 6a ba [2] 58 98 [2] 5e ad [2] 70 ad [2] 4f b1 }

  condition:
    any of them
}