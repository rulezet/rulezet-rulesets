rule TTP_XOR_WriteProcessMemory_5cd4 {
  strings:
    $key_5cd4 = { 0b a6 [2] 39 84 [2] 3f b1 [2] 11 b1 [2] 2e ad }

  condition:
    any of them
}