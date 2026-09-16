rule TTP_XOR_WriteProcessMemory_4b16 {
  strings:
    $key_4b16 = { 1c 64 [2] 2e 46 [2] 28 73 [2] 06 73 [2] 39 6f }

  condition:
    any of them
}