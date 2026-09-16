rule TTP_XOR_WriteProcessMemory_f6a8 {
  strings:
    $key_f6a8 = { a1 da [2] 93 f8 [2] 95 cd [2] bb cd [2] 84 d1 }

  condition:
    any of them
}