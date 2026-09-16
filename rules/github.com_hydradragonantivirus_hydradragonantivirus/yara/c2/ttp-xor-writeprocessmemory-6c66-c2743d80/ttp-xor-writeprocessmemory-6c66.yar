rule TTP_XOR_WriteProcessMemory_6c66 {
  strings:
    $key_6c66 = { 3b 14 [2] 09 36 [2] 0f 03 [2] 21 03 [2] 1e 1f }

  condition:
    any of them
}