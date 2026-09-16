rule TTP_XOR_WriteProcessMemory_cdc4 {
  strings:
    $key_cdc4 = { 9a b6 [2] a8 94 [2] ae a1 [2] 80 a1 [2] bf bd }

  condition:
    any of them
}