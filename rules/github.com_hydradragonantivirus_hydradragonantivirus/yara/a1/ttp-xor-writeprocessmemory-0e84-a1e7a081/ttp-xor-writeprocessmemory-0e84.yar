rule TTP_XOR_WriteProcessMemory_0e84 {
  strings:
    $key_0e84 = { 59 f6 [2] 6b d4 [2] 6d e1 [2] 43 e1 [2] 7c fd }

  condition:
    any of them
}