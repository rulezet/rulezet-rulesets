rule TTP_XOR_WriteProcessMemory_7f66 {
  strings:
    $key_7f66 = { 28 14 [2] 1a 36 [2] 1c 03 [2] 32 03 [2] 0d 1f }

  condition:
    any of them
}