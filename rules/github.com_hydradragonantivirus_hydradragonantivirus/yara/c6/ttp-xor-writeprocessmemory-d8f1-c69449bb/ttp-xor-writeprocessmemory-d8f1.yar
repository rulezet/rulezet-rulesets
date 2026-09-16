rule TTP_XOR_WriteProcessMemory_d8f1 {
  strings:
    $key_d8f1 = { 8f 83 [2] bd a1 [2] bb 94 [2] 95 94 [2] aa 88 }

  condition:
    any of them
}