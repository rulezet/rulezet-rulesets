rule TTP_XOR_WriteProcessMemory_1cd5 {
  strings:
    $key_1cd5 = { 4b a7 [2] 79 85 [2] 7f b0 [2] 51 b0 [2] 6e ac }

  condition:
    any of them
}