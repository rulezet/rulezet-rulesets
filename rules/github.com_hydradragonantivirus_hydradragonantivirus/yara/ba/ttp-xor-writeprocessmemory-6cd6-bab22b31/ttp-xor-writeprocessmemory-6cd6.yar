rule TTP_XOR_WriteProcessMemory_6cd6 {
  strings:
    $key_6cd6 = { 3b a4 [2] 09 86 [2] 0f b3 [2] 21 b3 [2] 1e af }

  condition:
    any of them
}