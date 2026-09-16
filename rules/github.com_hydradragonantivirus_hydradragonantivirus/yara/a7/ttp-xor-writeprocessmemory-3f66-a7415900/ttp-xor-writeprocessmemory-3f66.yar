rule TTP_XOR_WriteProcessMemory_3f66 {
  strings:
    $key_3f66 = { 68 14 [2] 5a 36 [2] 5c 03 [2] 72 03 [2] 4d 1f }

  condition:
    any of them
}