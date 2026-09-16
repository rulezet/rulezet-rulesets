rule TTP_XOR_WriteProcessMemory_c9e7 {
  strings:
    $key_c9e7 = { 9e 95 [2] ac b7 [2] aa 82 [2] 84 82 [2] bb 9e }

  condition:
    any of them
}