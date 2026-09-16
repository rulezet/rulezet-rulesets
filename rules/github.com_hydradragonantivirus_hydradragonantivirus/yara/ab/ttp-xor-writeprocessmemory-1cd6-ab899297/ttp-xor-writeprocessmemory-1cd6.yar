rule TTP_XOR_WriteProcessMemory_1cd6 {
  strings:
    $key_1cd6 = { 4b a4 [2] 79 86 [2] 7f b3 [2] 51 b3 [2] 6e af }

  condition:
    any of them
}