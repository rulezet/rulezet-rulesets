rule TTP_XOR_WriteProcessMemory_4b46 {
  strings:
    $key_4b46 = { 1c 34 [2] 2e 16 [2] 28 23 [2] 06 23 [2] 39 3f }

  condition:
    any of them
}