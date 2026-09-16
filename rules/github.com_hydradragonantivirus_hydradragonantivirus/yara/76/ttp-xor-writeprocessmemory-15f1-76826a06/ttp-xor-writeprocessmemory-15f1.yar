rule TTP_XOR_WriteProcessMemory_15f1 {
  strings:
    $key_15f1 = { 42 83 [2] 70 a1 [2] 76 94 [2] 58 94 [2] 67 88 }

  condition:
    any of them
}