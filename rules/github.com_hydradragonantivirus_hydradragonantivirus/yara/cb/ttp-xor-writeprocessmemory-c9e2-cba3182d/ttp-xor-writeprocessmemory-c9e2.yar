rule TTP_XOR_WriteProcessMemory_c9e2 {
  strings:
    $key_c9e2 = { 9e 90 [2] ac b2 [2] aa 87 [2] 84 87 [2] bb 9b }

  condition:
    any of them
}