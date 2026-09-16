rule TTP_XOR_WriteProcessMemory_41f1 {
  strings:
    $key_41f1 = { 16 83 [2] 24 a1 [2] 22 94 [2] 0c 94 [2] 33 88 }

  condition:
    any of them
}