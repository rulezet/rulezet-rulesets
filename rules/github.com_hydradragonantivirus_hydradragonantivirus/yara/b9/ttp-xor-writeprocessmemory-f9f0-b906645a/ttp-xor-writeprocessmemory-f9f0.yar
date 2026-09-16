rule TTP_XOR_WriteProcessMemory_f9f0 {
  strings:
    $key_f9f0 = { ae 82 [2] 9c a0 [2] 9a 95 [2] b4 95 [2] 8b 89 }

  condition:
    any of them
}