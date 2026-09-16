rule TTP_XOR_WriteProcessMemory_26e6 {
  strings:
    $key_26e6 = { 71 94 [2] 43 b6 [2] 45 83 [2] 6b 83 [2] 54 9f }

  condition:
    any of them
}