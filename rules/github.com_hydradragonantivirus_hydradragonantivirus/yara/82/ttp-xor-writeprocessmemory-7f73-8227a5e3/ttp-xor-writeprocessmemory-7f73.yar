rule TTP_XOR_WriteProcessMemory_7f73 {
  strings:
    $key_7f73 = { 28 01 [2] 1a 23 [2] 1c 16 [2] 32 16 [2] 0d 0a }

  condition:
    any of them
}