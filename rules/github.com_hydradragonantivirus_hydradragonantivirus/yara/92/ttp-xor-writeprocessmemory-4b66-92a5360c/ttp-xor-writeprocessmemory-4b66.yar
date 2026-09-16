rule TTP_XOR_WriteProcessMemory_4b66 {
  strings:
    $key_4b66 = { 1c 14 [2] 2e 36 [2] 28 03 [2] 06 03 [2] 39 1f }

  condition:
    any of them
}