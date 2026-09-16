rule TTP_XOR_WriteProcessMemory_7988 {
  strings:
    $key_7988 = { 2e fa [2] 1c d8 [2] 1a ed [2] 34 ed [2] 0b f1 }

  condition:
    any of them
}