rule TTP_XOR_WriteProcessMemory_e400 {
  strings:
    $key_e400 = { b3 72 [2] 81 50 [2] 87 65 [2] a9 65 [2] 96 79 }

  condition:
    any of them
}