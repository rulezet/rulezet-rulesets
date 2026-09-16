rule TTP_XOR_WriteProcessMemory_7c66 {
  strings:
    $key_7c66 = { 2b 14 [2] 19 36 [2] 1f 03 [2] 31 03 [2] 0e 1f }

  condition:
    any of them
}