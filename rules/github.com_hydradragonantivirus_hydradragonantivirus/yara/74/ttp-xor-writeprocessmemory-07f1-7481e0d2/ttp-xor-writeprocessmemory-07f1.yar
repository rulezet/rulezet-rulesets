rule TTP_XOR_WriteProcessMemory_07f1 {
  strings:
    $key_07f1 = { 50 83 [2] 62 a1 [2] 64 94 [2] 4a 94 [2] 75 88 }

  condition:
    any of them
}