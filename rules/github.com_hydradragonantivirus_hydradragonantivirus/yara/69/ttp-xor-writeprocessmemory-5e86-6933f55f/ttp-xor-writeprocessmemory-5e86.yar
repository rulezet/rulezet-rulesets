rule TTP_XOR_WriteProcessMemory_5e86 {
  strings:
    $key_5e86 = { 09 f4 [2] 3b d6 [2] 3d e3 [2] 13 e3 [2] 2c ff }

  condition:
    any of them
}