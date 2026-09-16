rule TTP_XOR_WriteProcessMemory_17f1 {
  strings:
    $key_17f1 = { 40 83 [2] 72 a1 [2] 74 94 [2] 5a 94 [2] 65 88 }

  condition:
    any of them
}