rule TTP_XOR_WriteProcessMemory_f9d1 {
  strings:
    $key_f9d1 = { ae a3 [2] 9c 81 [2] 9a b4 [2] b4 b4 [2] 8b a8 }

  condition:
    any of them
}