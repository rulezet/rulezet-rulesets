rule TTP_XOR_WriteProcessMemory_c9f8 {
  strings:
    $key_c9f8 = { 9e 8a [2] ac a8 [2] aa 9d [2] 84 9d [2] bb 81 }

  condition:
    any of them
}