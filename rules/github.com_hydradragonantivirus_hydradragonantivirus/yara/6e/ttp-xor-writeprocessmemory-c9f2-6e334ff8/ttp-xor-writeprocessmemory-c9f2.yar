rule TTP_XOR_WriteProcessMemory_c9f2 {
  strings:
    $key_c9f2 = { 9e 80 [2] ac a2 [2] aa 97 [2] 84 97 [2] bb 8b }

  condition:
    any of them
}