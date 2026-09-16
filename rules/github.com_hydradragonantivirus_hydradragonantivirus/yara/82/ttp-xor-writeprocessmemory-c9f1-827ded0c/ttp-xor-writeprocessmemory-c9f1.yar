rule TTP_XOR_WriteProcessMemory_c9f1 {
  strings:
    $key_c9f1 = { 9e 83 [2] ac a1 [2] aa 94 [2] 84 94 [2] bb 88 }

  condition:
    any of them
}