rule TTP_XOR_WriteProcessMemory_f3a8 {
  strings:
    $key_f3a8 = { a4 da [2] 96 f8 [2] 90 cd [2] be cd [2] 81 d1 }

  condition:
    any of them
}