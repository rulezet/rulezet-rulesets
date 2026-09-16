rule TTP_XOR_WriteProcessMemory_2273 {
  strings:
    $key_2273 = { 75 01 [2] 47 23 [2] 41 16 [2] 6f 16 [2] 50 0a }

  condition:
    any of them
}