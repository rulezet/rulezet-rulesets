rule TTP_XOR_WriteProcessMemory_27d0 {
  strings:
    $key_27d0 = { 70 a2 [2] 42 80 [2] 44 b5 [2] 6a b5 [2] 55 a9 }

  condition:
    any of them
}