rule TTP_XOR_WriteProcessMemory_7900 {
  strings:
    $key_7900 = { 2e 72 [2] 1c 50 [2] 1a 65 [2] 34 65 [2] 0b 79 }

  condition:
    any of them
}