rule TTP_XOR_WriteProcessMemory_7d64 {
  strings:
    $key_7d64 = { 2a 16 [2] 18 34 [2] 1e 01 [2] 30 01 [2] 0f 1d }

  condition:
    any of them
}