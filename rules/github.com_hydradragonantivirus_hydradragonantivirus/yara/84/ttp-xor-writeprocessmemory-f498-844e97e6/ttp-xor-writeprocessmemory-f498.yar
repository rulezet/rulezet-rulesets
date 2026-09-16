rule TTP_XOR_WriteProcessMemory_f498 {
  strings:
    $key_f498 = { a3 ea [2] 91 c8 [2] 97 fd [2] b9 fd [2] 86 e1 }

  condition:
    any of them
}