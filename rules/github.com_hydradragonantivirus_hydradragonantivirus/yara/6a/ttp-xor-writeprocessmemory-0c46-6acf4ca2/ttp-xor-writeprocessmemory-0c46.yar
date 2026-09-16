rule TTP_XOR_WriteProcessMemory_0c46 {
  strings:
    $key_0c46 = { 5b 34 [2] 69 16 [2] 6f 23 [2] 41 23 [2] 7e 3f }

  condition:
    any of them
}