rule TTP_XOR_WriteProcessMemory_5336 {
  strings:
    $key_5336 = { 04 44 [2] 36 66 [2] 30 53 [2] 1e 53 [2] 21 4f }

  condition:
    any of them
}