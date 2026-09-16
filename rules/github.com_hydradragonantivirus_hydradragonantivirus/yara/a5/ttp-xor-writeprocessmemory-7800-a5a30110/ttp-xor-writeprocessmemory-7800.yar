rule TTP_XOR_WriteProcessMemory_7800 {
  strings:
    $key_7800 = { 2f 72 [2] 1d 50 [2] 1b 65 [2] 35 65 [2] 0a 79 }

  condition:
    any of them
}