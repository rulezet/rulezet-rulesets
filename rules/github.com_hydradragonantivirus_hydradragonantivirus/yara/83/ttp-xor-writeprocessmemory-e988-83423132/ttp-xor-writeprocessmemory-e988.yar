rule TTP_XOR_WriteProcessMemory_e988 {
  strings:
    $key_e988 = { be fa [2] 8c d8 [2] 8a ed [2] a4 ed [2] 9b f1 }

  condition:
    any of them
}