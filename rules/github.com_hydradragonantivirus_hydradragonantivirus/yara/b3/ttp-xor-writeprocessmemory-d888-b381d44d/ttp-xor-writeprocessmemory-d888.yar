rule TTP_XOR_WriteProcessMemory_d888 {
  strings:
    $key_d888 = { 8f fa [2] bd d8 [2] bb ed [2] 95 ed [2] aa f1 }

  condition:
    any of them
}