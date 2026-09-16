rule TTP_XOR_WriteProcessMemory_f690 {
  strings:
    $key_f690 = { a1 e2 [2] 93 c0 [2] 95 f5 [2] bb f5 [2] 84 e9 }

  condition:
    any of them
}