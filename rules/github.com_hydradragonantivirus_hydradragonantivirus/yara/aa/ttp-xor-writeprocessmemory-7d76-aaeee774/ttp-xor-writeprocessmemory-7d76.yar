rule TTP_XOR_WriteProcessMemory_7d76 {
  strings:
    $key_7d76 = { 2a 04 [2] 18 26 [2] 1e 13 [2] 30 13 [2] 0f 0f }

  condition:
    any of them
}