rule TTP_XOR_WriteProcessMemory_6dc8 {
  strings:
    $key_6dc8 = { 3a ba [2] 08 98 [2] 0e ad [2] 20 ad [2] 1f b1 }

  condition:
    any of them
}