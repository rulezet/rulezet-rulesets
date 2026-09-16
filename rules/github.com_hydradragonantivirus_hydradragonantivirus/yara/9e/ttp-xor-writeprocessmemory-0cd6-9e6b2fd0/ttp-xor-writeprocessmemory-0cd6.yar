rule TTP_XOR_WriteProcessMemory_0cd6 {
  strings:
    $key_0cd6 = { 5b a4 [2] 69 86 [2] 6f b3 [2] 41 b3 [2] 7e af }

  condition:
    any of them
}