rule TTP_XOR_WriteProcessMemory_29d2 {
  strings:
    $key_29d2 = { 7e a0 [2] 4c 82 [2] 4a b7 [2] 64 b7 [2] 5b ab }

  condition:
    any of them
}