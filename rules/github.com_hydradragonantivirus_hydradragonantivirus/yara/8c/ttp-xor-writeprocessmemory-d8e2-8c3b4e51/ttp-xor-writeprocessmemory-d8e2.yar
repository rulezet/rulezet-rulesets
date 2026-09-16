rule TTP_XOR_WriteProcessMemory_d8e2 {
  strings:
    $key_d8e2 = { 8f 90 [2] bd b2 [2] bb 87 [2] 95 87 [2] aa 9b }

  condition:
    any of them
}