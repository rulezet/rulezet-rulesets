rule TTP_XOR_WriteProcessMemory_f9d0 {
  strings:
    $key_f9d0 = { ae a2 [2] 9c 80 [2] 9a b5 [2] b4 b5 [2] 8b a9 }

  condition:
    any of them
}