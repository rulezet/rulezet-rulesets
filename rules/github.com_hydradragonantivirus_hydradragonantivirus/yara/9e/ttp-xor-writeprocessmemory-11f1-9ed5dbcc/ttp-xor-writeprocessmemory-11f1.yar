rule TTP_XOR_WriteProcessMemory_11f1 {
  strings:
    $key_11f1 = { 46 83 [2] 74 a1 [2] 72 94 [2] 5c 94 [2] 63 88 }

  condition:
    any of them
}