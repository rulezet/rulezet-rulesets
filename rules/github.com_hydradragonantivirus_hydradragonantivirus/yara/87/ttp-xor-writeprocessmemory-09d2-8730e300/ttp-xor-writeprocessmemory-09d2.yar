rule TTP_XOR_WriteProcessMemory_09d2 {
  strings:
    $key_09d2 = { 5e a0 [2] 6c 82 [2] 6a b7 [2] 44 b7 [2] 7b ab }

  condition:
    any of them
}