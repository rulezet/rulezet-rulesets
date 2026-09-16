rule TTP_XOR_WriteProcessMemory_49d4 {
  strings:
    $key_49d4 = { 1e a6 [2] 2c 84 [2] 2a b1 [2] 04 b1 [2] 3b ad }

  condition:
    any of them
}