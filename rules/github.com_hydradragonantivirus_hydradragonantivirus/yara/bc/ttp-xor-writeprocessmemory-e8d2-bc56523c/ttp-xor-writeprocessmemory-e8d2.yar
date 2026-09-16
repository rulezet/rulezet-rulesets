rule TTP_XOR_WriteProcessMemory_e8d2 {
  strings:
    $key_e8d2 = { bf a0 [2] 8d 82 [2] 8b b7 [2] a5 b7 [2] 9a ab }

  condition:
    any of them
}