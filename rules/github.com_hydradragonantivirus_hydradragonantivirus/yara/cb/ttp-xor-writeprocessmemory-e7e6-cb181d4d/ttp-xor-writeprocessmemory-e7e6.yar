rule TTP_XOR_WriteProcessMemory_e7e6 {
  strings:
    $key_e7e6 = { b0 94 [2] 82 b6 [2] 84 83 [2] aa 83 [2] 95 9f }

  condition:
    any of them
}