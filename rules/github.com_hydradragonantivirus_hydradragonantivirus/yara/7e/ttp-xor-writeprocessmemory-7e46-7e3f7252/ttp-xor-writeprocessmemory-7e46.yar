rule TTP_XOR_WriteProcessMemory_7e46 {
  strings:
    $key_7e46 = { 29 34 [2] 1b 16 [2] 1d 23 [2] 33 23 [2] 0c 3f }

  condition:
    any of them
}