rule TTP_XOR_WriteProcessMemory_7cd5 {
  strings:
    $key_7cd5 = { 2b a7 [2] 19 85 [2] 1f b0 [2] 31 b0 [2] 0e ac }

  condition:
    any of them
}