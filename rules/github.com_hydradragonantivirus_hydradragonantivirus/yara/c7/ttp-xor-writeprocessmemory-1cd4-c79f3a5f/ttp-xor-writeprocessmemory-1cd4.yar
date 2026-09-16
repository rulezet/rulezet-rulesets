rule TTP_XOR_WriteProcessMemory_1cd4 {
  strings:
    $key_1cd4 = { 4b a6 [2] 79 84 [2] 7f b1 [2] 51 b1 [2] 6e ad }

  condition:
    any of them
}