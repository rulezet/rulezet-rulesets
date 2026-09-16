rule TTP_XOR_WriteProcessMemory_47f1 {
  strings:
    $key_47f1 = { 10 83 [2] 22 a1 [2] 24 94 [2] 0a 94 [2] 35 88 }

  condition:
    any of them
}