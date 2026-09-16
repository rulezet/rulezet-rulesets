rule TTP_XOR_WriteProcessMemory_21f1 {
  strings:
    $key_21f1 = { 76 83 [2] 44 a1 [2] 42 94 [2] 6c 94 [2] 53 88 }

  condition:
    any of them
}