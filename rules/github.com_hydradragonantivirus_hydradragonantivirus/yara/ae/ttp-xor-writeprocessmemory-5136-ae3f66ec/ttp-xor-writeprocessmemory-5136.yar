rule TTP_XOR_WriteProcessMemory_5136 {
  strings:
    $key_5136 = { 06 44 [2] 34 66 [2] 32 53 [2] 1c 53 [2] 23 4f }

  condition:
    any of them
}