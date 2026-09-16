rule TTP_XOR_WriteProcessMemory_69d6 {
  strings:
    $key_69d6 = { 3e a4 [2] 0c 86 [2] 0a b3 [2] 24 b3 [2] 1b af }

  condition:
    any of them
}