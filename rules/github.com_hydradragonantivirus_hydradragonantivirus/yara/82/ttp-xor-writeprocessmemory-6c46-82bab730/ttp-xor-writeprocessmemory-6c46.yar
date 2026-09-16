rule TTP_XOR_WriteProcessMemory_6c46 {
  strings:
    $key_6c46 = { 3b 34 [2] 09 16 [2] 0f 23 [2] 21 23 [2] 1e 3f }

  condition:
    any of them
}