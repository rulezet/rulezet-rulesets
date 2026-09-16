rule TTP_XOR_WriteProcessMemory_5900 {
  strings:
    $key_5900 = { 0e 72 [2] 3c 50 [2] 3a 65 [2] 14 65 [2] 2b 79 }

  condition:
    any of them
}