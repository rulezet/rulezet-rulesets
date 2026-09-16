rule TTP_XOR_WriteProcessMemory_f9d2 {
  strings:
    $key_f9d2 = { ae a0 [2] 9c 82 [2] 9a b7 [2] b4 b7 [2] 8b ab }

  condition:
    any of them
}