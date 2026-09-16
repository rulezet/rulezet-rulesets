rule TTP_XOR_WriteProcessMemory_c972 {
  strings:
    $key_c972 = { 9e 00 [2] ac 22 [2] aa 17 [2] 84 17 [2] bb 0b }

  condition:
    any of them
}