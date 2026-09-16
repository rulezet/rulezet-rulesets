rule TTP_XOR_WriteProcessMemory_e656 {
  strings:
    $key_e656 = { b1 24 [2] 83 06 [2] 85 33 [2] ab 33 [2] 94 2f }

  condition:
    any of them
}