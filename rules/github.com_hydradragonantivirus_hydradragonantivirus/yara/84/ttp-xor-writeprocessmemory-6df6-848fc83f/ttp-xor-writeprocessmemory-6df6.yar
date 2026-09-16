rule TTP_XOR_WriteProcessMemory_6df6 {
  strings:
    $key_6df6 = { 3a 84 [2] 08 a6 [2] 0e 93 [2] 20 93 [2] 1f 8f }

  condition:
    any of them
}