rule TTP_XOR_WriteProcessMemory_69d2 {
  strings:
    $key_69d2 = { 3e a0 [2] 0c 82 [2] 0a b7 [2] 24 b7 [2] 1b ab }

  condition:
    any of them
}