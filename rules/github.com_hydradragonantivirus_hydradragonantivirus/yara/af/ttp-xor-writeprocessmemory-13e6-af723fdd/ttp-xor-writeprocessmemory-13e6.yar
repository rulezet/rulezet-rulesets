rule TTP_XOR_WriteProcessMemory_13e6 {
  strings:
    $key_13e6 = { 44 94 [2] 76 b6 [2] 70 83 [2] 5e 83 [2] 61 9f }

  condition:
    any of them
}