rule TTP_XOR_WriteProcessMemory_79d6 {
  strings:
    $key_79d6 = { 2e a4 [2] 1c 86 [2] 1a b3 [2] 34 b3 [2] 0b af }

  condition:
    any of them
}