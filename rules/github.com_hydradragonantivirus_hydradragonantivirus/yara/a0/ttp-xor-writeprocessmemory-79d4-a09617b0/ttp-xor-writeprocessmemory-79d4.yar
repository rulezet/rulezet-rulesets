rule TTP_XOR_WriteProcessMemory_79d4 {
  strings:
    $key_79d4 = { 2e a6 [2] 1c 84 [2] 1a b1 [2] 34 b1 [2] 0b ad }

  condition:
    any of them
}