rule TTP_XOR_WriteProcessMemory_4c66 {
  strings:
    $key_4c66 = { 1b 14 [2] 29 36 [2] 2f 03 [2] 01 03 [2] 3e 1f }

  condition:
    any of them
}