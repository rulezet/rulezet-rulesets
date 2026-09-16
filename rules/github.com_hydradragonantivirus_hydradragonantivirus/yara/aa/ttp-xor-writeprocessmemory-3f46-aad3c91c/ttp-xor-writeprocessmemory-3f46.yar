rule TTP_XOR_WriteProcessMemory_3f46 {
  strings:
    $key_3f46 = { 68 34 [2] 5a 16 [2] 5c 23 [2] 72 23 [2] 4d 3f }

  condition:
    any of them
}