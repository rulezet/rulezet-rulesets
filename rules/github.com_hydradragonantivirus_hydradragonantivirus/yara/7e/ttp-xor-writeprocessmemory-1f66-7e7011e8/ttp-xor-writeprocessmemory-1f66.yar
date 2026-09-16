rule TTP_XOR_WriteProcessMemory_1f66 {
  strings:
    $key_1f66 = { 48 14 [2] 7a 36 [2] 7c 03 [2] 52 03 [2] 6d 1f }

  condition:
    any of them
}