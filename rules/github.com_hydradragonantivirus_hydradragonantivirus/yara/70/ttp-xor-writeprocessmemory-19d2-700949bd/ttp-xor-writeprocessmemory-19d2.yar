rule TTP_XOR_WriteProcessMemory_19d2 {
  strings:
    $key_19d2 = { 4e a0 [2] 7c 82 [2] 7a b7 [2] 54 b7 [2] 6b ab }

  condition:
    any of them
}