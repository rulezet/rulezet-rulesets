rule TTP_XOR_WriteProcessMemory_7ff2 {
  strings:
    $key_7ff2 = { 28 80 [2] 1a a2 [2] 1c 97 [2] 32 97 [2] 0d 8b }

  condition:
    any of them
}