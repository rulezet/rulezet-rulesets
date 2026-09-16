rule TTP_XOR_WriteProcessMemory_7cd0 {
  strings:
    $key_7cd0 = { 2b a2 [2] 19 80 [2] 1f b5 [2] 31 b5 [2] 0e a9 }

  condition:
    any of them
}