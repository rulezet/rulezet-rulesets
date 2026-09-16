rule TTP_XOR_WriteProcessMemory_1f46 {
  strings:
    $key_1f46 = { 48 34 [2] 7a 16 [2] 7c 23 [2] 52 23 [2] 6d 3f }

  condition:
    any of them
}