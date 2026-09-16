rule TTP_XOR_WriteProcessMemory_64f1 {
  strings:
    $key_64f1 = { 33 83 [2] 01 a1 [2] 07 94 [2] 29 94 [2] 16 88 }

  condition:
    any of them
}