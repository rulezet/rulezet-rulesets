rule TTP_XOR_WriteProcessMemory_7ff3 {
  strings:
    $key_7ff3 = { 28 81 [2] 1a a3 [2] 1c 96 [2] 32 96 [2] 0d 8a }

  condition:
    any of them
}