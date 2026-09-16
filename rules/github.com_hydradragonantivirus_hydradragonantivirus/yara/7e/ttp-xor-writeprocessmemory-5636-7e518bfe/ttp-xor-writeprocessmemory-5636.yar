rule TTP_XOR_WriteProcessMemory_5636 {
  strings:
    $key_5636 = { 01 44 [2] 33 66 [2] 35 53 [2] 1b 53 [2] 24 4f }

  condition:
    any of them
}