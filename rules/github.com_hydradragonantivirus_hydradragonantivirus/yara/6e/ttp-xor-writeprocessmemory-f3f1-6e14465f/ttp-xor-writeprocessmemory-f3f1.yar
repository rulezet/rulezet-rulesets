rule TTP_XOR_WriteProcessMemory_f3f1 {
  strings:
    $key_f3f1 = { a4 83 [2] 96 a1 [2] 90 94 [2] be 94 [2] 81 88 }

  condition:
    any of them
}