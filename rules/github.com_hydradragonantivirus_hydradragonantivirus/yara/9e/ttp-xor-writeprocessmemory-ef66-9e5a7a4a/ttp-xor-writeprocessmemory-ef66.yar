rule TTP_XOR_WriteProcessMemory_ef66 {
  strings:
    $key_ef66 = { b8 14 [2] 8a 36 [2] 8c 03 [2] a2 03 [2] 9d 1f }

  condition:
    any of them
}