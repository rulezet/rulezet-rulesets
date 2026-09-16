rule TTP_XOR_WriteProcessMemory_2646 {
  strings:
    $key_2646 = { 71 34 [2] 43 16 [2] 45 23 [2] 6b 23 [2] 54 3f }

  condition:
    any of them
}