rule TTP_XOR_WriteProcessMemory_78f6 {
  strings:
    $key_78f6 = { 2f 84 [2] 1d a6 [2] 1b 93 [2] 35 93 [2] 0a 8f }

  condition:
    any of them
}