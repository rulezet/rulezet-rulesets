rule TTP_XOR_WriteProcessMemory_25f1 {
  strings:
    $key_25f1 = { 72 83 [2] 40 a1 [2] 46 94 [2] 68 94 [2] 57 88 }

  condition:
    any of them
}