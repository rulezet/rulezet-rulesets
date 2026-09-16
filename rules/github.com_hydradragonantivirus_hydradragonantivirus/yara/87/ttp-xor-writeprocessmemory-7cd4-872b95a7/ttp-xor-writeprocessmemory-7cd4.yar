rule TTP_XOR_WriteProcessMemory_7cd4 {
  strings:
    $key_7cd4 = { 2b a6 [2] 19 84 [2] 1f b1 [2] 31 b1 [2] 0e ad }

  condition:
    any of them
}