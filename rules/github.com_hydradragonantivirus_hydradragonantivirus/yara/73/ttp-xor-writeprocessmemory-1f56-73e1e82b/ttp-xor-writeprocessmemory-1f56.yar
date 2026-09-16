rule TTP_XOR_WriteProcessMemory_1f56 {
  strings:
    $key_1f56 = { 48 24 [2] 7a 06 [2] 7c 33 [2] 52 33 [2] 6d 2f }

  condition:
    any of them
}