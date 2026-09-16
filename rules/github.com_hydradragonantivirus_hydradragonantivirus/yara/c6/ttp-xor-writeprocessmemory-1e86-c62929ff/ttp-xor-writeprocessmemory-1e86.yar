rule TTP_XOR_WriteProcessMemory_1e86 {
  strings:
    $key_1e86 = { 49 f4 [2] 7b d6 [2] 7d e3 [2] 53 e3 [2] 6c ff }

  condition:
    any of them
}