rule TTP_XOR_WriteProcessMemory_7cd2 {
  strings:
    $key_7cd2 = { 2b a0 [2] 19 82 [2] 1f b7 [2] 31 b7 [2] 0e ab }

  condition:
    any of them
}