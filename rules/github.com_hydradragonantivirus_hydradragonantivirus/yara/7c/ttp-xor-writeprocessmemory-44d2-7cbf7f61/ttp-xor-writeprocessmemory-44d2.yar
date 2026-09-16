rule TTP_XOR_WriteProcessMemory_44d2 {
  strings:
    $key_44d2 = { 13 a0 [2] 21 82 [2] 27 b7 [2] 09 b7 [2] 36 ab }

  condition:
    any of them
}