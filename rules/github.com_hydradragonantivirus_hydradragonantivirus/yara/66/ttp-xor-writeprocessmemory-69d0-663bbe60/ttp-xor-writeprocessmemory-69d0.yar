rule TTP_XOR_WriteProcessMemory_69d0 {
  strings:
    $key_69d0 = { 3e a2 [2] 0c 80 [2] 0a b5 [2] 24 b5 [2] 1b a9 }

  condition:
    any of them
}