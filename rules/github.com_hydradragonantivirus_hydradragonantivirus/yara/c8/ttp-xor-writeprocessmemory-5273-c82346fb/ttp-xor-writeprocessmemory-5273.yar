rule TTP_XOR_WriteProcessMemory_5273 {
  strings:
    $key_5273 = { 05 01 [2] 37 23 [2] 31 16 [2] 1f 16 [2] 20 0a }

  condition:
    any of them
}