rule TTP_XOR_WriteProcessMemory_5955 {
  strings:
    $key_5955 = { 0e 27 [2] 3c 05 [2] 3a 30 [2] 14 30 [2] 2b 2c }

  condition:
    any of them
}