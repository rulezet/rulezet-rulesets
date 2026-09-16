rule TTP_XOR_WriteProcessMemory_f297 {
  strings:
    $key_f297 = { a5 e5 [2] 97 c7 [2] 91 f2 [2] bf f2 [2] 80 ee }

  condition:
    any of them
}