rule TTP_XOR_WriteProcessMemory_5d46 {
  strings:
    $key_5d46 = { 0a 34 [2] 38 16 [2] 3e 23 [2] 10 23 [2] 2f 3f }

  condition:
    any of them
}