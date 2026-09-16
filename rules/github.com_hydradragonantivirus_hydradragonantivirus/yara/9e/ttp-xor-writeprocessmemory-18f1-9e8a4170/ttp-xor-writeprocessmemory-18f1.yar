rule TTP_XOR_WriteProcessMemory_18f1 {
  strings:
    $key_18f1 = { 4f 83 [2] 7d a1 [2] 7b 94 [2] 55 94 [2] 6a 88 }

  condition:
    any of them
}