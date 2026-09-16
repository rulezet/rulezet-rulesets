rule TTP_XOR_WriteProcessMemory_c9f3 {
  strings:
    $key_c9f3 = { 9e 81 [2] ac a3 [2] aa 96 [2] 84 96 [2] bb 8a }

  condition:
    any of them
}