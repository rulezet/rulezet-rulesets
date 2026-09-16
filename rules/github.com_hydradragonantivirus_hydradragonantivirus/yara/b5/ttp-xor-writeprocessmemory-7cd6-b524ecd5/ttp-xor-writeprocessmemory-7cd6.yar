rule TTP_XOR_WriteProcessMemory_7cd6 {
  strings:
    $key_7cd6 = { 2b a4 [2] 19 86 [2] 1f b3 [2] 31 b3 [2] 0e af }

  condition:
    any of them
}