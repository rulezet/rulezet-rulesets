rule TTP_XOR_WriteProcessMemory_3cd6 {
  strings:
    $key_3cd6 = { 6b a4 [2] 59 86 [2] 5f b3 [2] 71 b3 [2] 4e af }

  condition:
    any of them
}