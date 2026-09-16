rule TTP_XOR_WriteProcessMemory_5d00 {
  strings:
    $key_5d00 = { 0a 72 [2] 38 50 [2] 3e 65 [2] 10 65 [2] 2f 79 }

  condition:
    any of them
}