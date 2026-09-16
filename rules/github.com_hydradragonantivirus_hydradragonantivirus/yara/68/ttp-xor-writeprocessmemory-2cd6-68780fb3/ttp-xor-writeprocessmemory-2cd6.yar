rule TTP_XOR_WriteProcessMemory_2cd6 {
  strings:
    $key_2cd6 = { 7b a4 [2] 49 86 [2] 4f b3 [2] 61 b3 [2] 5e af }

  condition:
    any of them
}