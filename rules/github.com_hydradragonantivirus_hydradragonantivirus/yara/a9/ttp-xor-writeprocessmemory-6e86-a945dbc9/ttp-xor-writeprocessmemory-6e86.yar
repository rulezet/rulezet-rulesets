rule TTP_XOR_WriteProcessMemory_6e86 {
  strings:
    $key_6e86 = { 39 f4 [2] 0b d6 [2] 0d e3 [2] 23 e3 [2] 1c ff }

  condition:
    any of them
}