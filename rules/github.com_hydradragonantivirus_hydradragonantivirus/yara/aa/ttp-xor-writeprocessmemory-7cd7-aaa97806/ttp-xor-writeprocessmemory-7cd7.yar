rule TTP_XOR_WriteProcessMemory_7cd7 {
  strings:
    $key_7cd7 = { 2b a5 [2] 19 87 [2] 1f b2 [2] 31 b2 [2] 0e ae }

  condition:
    any of them
}