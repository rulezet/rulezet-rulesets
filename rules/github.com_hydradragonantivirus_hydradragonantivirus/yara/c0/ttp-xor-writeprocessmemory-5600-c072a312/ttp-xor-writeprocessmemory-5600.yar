rule TTP_XOR_WriteProcessMemory_5600 {
  strings:
    $key_5600 = { 01 72 [2] 33 50 [2] 35 65 [2] 1b 65 [2] 24 79 }

  condition:
    any of them
}