rule TTP_XOR_WriteProcessMemory_4dc4 {
  strings:
    $key_4dc4 = { 1a b6 [2] 28 94 [2] 2e a1 [2] 00 a1 [2] 3f bd }

  condition:
    any of them
}