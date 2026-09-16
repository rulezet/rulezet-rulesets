rule TTP_XOR_WriteProcessMemory_f694 {
  strings:
    $key_f694 = { a1 e6 [2] 93 c4 [2] 95 f1 [2] bb f1 [2] 84 ed }

  condition:
    any of them
}